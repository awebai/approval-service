package verify

import (
	"encoding/json"
	"strings"
)

// These are independently checked SDK/lifecycle ports, NEVER fields trusted
// from C. Effects, nonce consumption and grant storage stay with the enforcer.
type RootIdentity struct {
	ID, CurrentKey string
	ContinuousKeys []string
}

// PersonContinuity is checked FROM the receipt key TO a chosen as-of key, not
// the person's whole creation history. Since is the existing checked history
// basis; it is never a WebAuthn signing time or a date inferred from R.
type PersonContinuity struct {
	FromKey, CurrentKey, Mode string
	Since                     *int64
}

type CheckedRootAgent struct {
	Approval                                                    CheckedApproval
	Person, RootID, RootKey, Mode, Enforcer, Status, Continuity string
	Teams                                                       []string
	Since                                                       *int64
}

type RootAgentInput struct {
	ExpectedRequest                map[string]any
	Root                           RootIdentity
	Trust                          Trust
	Now                            int64
	Presenter                      map[string]any
	RequiredGrade                  string
	NonceKeys                      map[string][]byte
	Origin, Audience, EnforcerKind string
	OwnedTeams                     []string
	Revision                       int64
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func rootTarget(request map[string]any, root RootIdentity, trust Trust, parentPerson string) (map[string]any, error) {
	if err := CheckDefinition(request); err != nil {
		return nil, err
	}
	if text(object(request, "definition"), "id") != "agent.root.authorize" {
		return nil, refuse("root_act_invalid")
	}
	t := object(object(request, "act"), "target")
	if text(t, "person") != trust.Person || text(request, "approver") != trust.Person || parentPerson != trust.Person || text(request, "organisation") != trust.Organisation {
		return nil, refuse("root_person_mismatch")
	}
	if text(t, "root_id") != root.ID {
		return nil, refuse("root_identity_mismatch")
	}
	if len(root.ContinuousKeys) == 0 || !contains(root.ContinuousKeys, root.CurrentKey) {
		return nil, refuse("root_history_unavailable")
	}
	if !contains(root.ContinuousKeys, text(t, "root_key")) {
		return nil, refuse("root_key_discontinuous")
	}
	for _, team := range t["teams"].([]any) {
		_, domain, _ := strings.Cut(team.(string), ":")
		if domain != text(request, "organisation") {
			return nil, refuse("root_team_organisation_mismatch")
		}
	}
	return t, nil
}

func rootResult(approval CheckedApproval, request, target map[string]any, status, continuity string, since *int64) CheckedRootAgent {
	teams := make([]string, len(target["teams"].([]any)))
	for i, item := range target["teams"].([]any) {
		teams[i] = item.(string)
	}
	return CheckedRootAgent{Approval: approval, Person: text(target, "person"), RootID: text(target, "root_id"), RootKey: text(target, "root_key"), Mode: text(target, "mode"), Enforcer: text(object(request, "enforcer"), "audience"), Teams: teams, Status: status, Continuity: continuity, Since: since}
}

// CheckRootAgentPresentation returns the WHOLE replacement list (empty
// withdraws), never a union. The enforcer commits it with nonce consumption.
// Its own configuration supplies the audience/kind, owned teams and revision.
// An aw enforcer accepts ONLY an empty teams list.
func CheckRootAgentPresentation(value map[string]any, in RootAgentInput) (CheckedRootAgent, error) {
	var out CheckedRootAgent
	t, err := rootTarget(in.ExpectedRequest, in.Root, in.Trust, in.Trust.Person)
	if err != nil {
		return out, err
	}
	if text(object(in.ExpectedRequest, "enforcer"), "audience") != in.Audience {
		return out, refuse("root_enforcer_mismatch")
	}
	if in.EnforcerKind != "aw" && in.EnforcerKind != "key_holder" && in.EnforcerKind != "cloud_key_process" {
		return out, refuse("root_enforcer_invalid")
	}
	if in.EnforcerKind == "aw" && len(t["teams"].([]any)) != 0 {
		return out, refuse("root_teams_not_supported")
	}
	for _, team := range t["teams"].([]any) {
		if !contains(in.OwnedTeams, team.(string)) {
			return out, refuse("root_team_not_owned")
		}
	}
	if number(object(in.ExpectedRequest, "act"), "expected_revision") != in.Revision {
		return out, refuse("root_revision_mismatch")
	}
	checked, err := CheckPresentation(value, EffectInputs{ExpectedRequest: in.ExpectedRequest, Presenter: in.Presenter, Trust: in.Trust, Now: in.Now, RequiredGrade: in.RequiredGrade, NonceKeys: in.NonceKeys}, in.Origin)
	if err != nil {
		return out, err
	}
	return rootResult(checked, in.ExpectedRequest, t, "checked", "unknown", nil), nil
}

// VerifyRootAgentProof checks historical C on an independently checked HUMAN
// -> root link. It has no live effect clock or enforcer-kind restriction.
// Missing/invalid/unsupported evidence never changes the outer chain verdict.
func VerifyRootAgentProof(value map[string]any, root RootIdentity, parentPerson string, trust Trust, history PersonContinuity) (CheckedRootAgent, error) {
	var out CheckedRootAgent
	if n, ok := value["version"].(json.Number); ok && n != "1" {
		return out, refuse("root_proof_unsupported")
	}
	if validate("root_agent_proof", value) != nil {
		return out, refuse("root_proof_invalid")
	}
	receipt := object(value, "receipt")
	raw, err := decode(text(receipt, "request_bytes"))
	if err != nil {
		return out, refuse("root_proof_invalid")
	}
	r, err := Parse(raw)
	if err != nil {
		return out, refuse("root_proof_invalid")
	}
	t, err := rootTarget(r, root, trust, parentPerson)
	if err != nil {
		return out, err
	}
	checked, err := VerifyHistorical(receipt, r, trust)
	if err != nil {
		return out, err
	}
	if history.FromKey != trust.IdentityKey || history.CurrentKey == "" || (history.Mode != "unbroken" && history.Mode != "assisted" && history.Mode != "recreated" && history.Mode != "unknown") || (history.Mode != "unknown" && (history.Since == nil || *history.Since < 0)) {
		return out, refuse("root_history_unavailable")
	}
	status := map[string]string{"unbroken": "approved", "assisted": "approval_predates_break", "recreated": "approval_predates_break", "unknown": "continuity_unknown"}[history.Mode]
	return rootResult(checked, r, t, status, history.Mode, history.Since), nil
}
