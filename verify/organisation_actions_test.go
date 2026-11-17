package verify

import (
    "encoding/json"
    "testing"
)

func TestOrganisationActionDefinitions(t *testing.T) {
    for _, id := range []string{"organisation.person.admit", "organisation.human_approval.change"} {
        ref, err := DefinitionRef(id)
        if err != nil { t.Fatal(err) }
        v, err := definitionBody(id)
        if err != nil { t.Fatal(err) }
        if v["policy_organisation"] != "act.target.organisation" || ref["version"] != json.Number("1") {
            t.Fatalf("wrong organisation selector for %s", id)
        }
    }
}
