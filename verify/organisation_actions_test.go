package verify

import (
	"encoding/json"
	"testing"
)

func TestOrganisationActionDefinitions(t *testing.T) {
	for _, id := range []string{"organisation.person.admit", "organisation.human_approval.change"} {
		ref, err := DefinitionRef(id)
		if err != nil {
			t.Fatal(err)
		}
		v, err := definitionBody(id)
		if err != nil {
			t.Fatal(err)
		}
		if v["policy_organisation"] != "act.target.organisation" || ref["version"] != json.Number("1") {
			t.Fatalf("wrong organisation selector for %s", id)
		}
	}
}

func TestOrganisationSharedBytes(t *testing.T) {
	for _, value := range seamCases(t, "organisation-actions") {
		c := value.(map[string]any)
		t.Run(text(c, "id"), func(t *testing.T) {
			err := CheckDefinition(object(c, "request"))
			if err == nil && text(c, "phase") == "receipt" {
				nonce, _ := decode(text(c, "nonce_key"))
				var result CheckedApproval
				result, err = VerifyForEffect(object(c, "receipt"), EffectInputs{
					ExpectedRequest: object(c, "request"), Trust: *seamTrust(t, c["trust"]),
					Now: number(c, "now"), RequiredGrade: text(c, "required_grade"),
					Presenter: object(c, "presenter"), NonceKeys: map[string][]byte{"k1": nonce},
				})
				if err == nil && result.Person != text(c, "expected_person") {
					t.Fatal("wrong approver")
				}
			}
			if (err == nil) != c["accept"].(bool) {
				t.Fatalf("unexpected result: %v", err)
			}
			if err != nil && err.Error() != text(c, "expected_error") {
				t.Fatal(err)
			}
		})
	}
}
