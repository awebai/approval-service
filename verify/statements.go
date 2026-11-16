package verify

import "encoding/json"

// EnrollmentEvidence contains authenticated issuer facts and a separately
// checked optional assertion. Neither field is live effect authorization.
type EnrollmentEvidence struct {
	Person, Credential, Grade, ProofStatus string
	Since                                  int64
}

func StatementDefinition(name string) (map[string]any, error) {
	definitions, ok := wireSchema["x-statement-definitions"].(map[string]any)
	if !ok {
		return nil, refuse("statement_unavailable")
	}
	source, ok := definitions[name].(map[string]any)
	if !ok {
		return nil, refuse("statement_unavailable")
	}
	raw, err := json.Marshal(source)
	if err != nil {
		return nil, err
	}
	value, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	value["body_schema"] = wireSchema["$defs"].(map[string]any)[text(value, "body_schema")]
	value["signature_domain"] = string(domain(text(value, "signature_domain")))
	// Return owned data; consumers cannot mutate the process schema.
	raw, err = json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func checkEnrollmentStatement(statement map[string]any, trust Trust) (map[string]any, error) {
	e, ok := statement["evidence"].(map[string]any)
	if !ok {
		return nil, refuse("enrollment_evidence_invalid")
	}
	version, ok := e["version"].(json.Number)
	if !ok {
		return nil, refuse("enrollment_evidence_invalid")
	}
	kind, _ := e["kind"].(string)
	if version != "1" || kind != "human_enrolled_later" {
		return nil, refuse("enrollment_evidence_unsupported")
	}
	if validate("later_enrollment_evidence", statement) != nil {
		return nil, refuse("enrollment_evidence_invalid")
	}
	raw, err := preimage("later_enrollment_evidence", e)
	if err != nil {
		return nil, err
	}
	if err = signature(trust.Issuer, text(statement, "signature"), raw); err != nil {
		return nil, err
	}
	subject := map[string]any{"id": trust.Person, "certificate": trust.Certificate, "key": trust.IdentityKey}
	if !equalValue(e["subject"], subject) || text(e, "organisation") != trust.Organisation || text(e, "issuer") != trust.Issuer {
		return nil, refuse("evidence_subject_mismatch")
	}
	return e, nil
}

func matchEnrollmentConfirmation(e, receipt map[string]any, checked CheckedApproval, bh string) error {
	f := object(e, "enrollment")
	ch, err := Commitment("receipt_commitment", receipt)
	if err != nil {
		return err
	}
	if text(e, "binding_commitment") != bh || text(f, "credential") != checked.Credential || text(f, "grade") != checked.Grade || text(f, "confirmation_receipt_commitment") != ch {
		return refuse("evidence_binding_mismatch")
	}
	if transition, ok := e["transition"].(map[string]any); ok && text(transition, "confirmation_receipt_commitment") != ch {
		return refuse("evidence_binding_mismatch")
	}
	return nil
}

// VerifyEnrollmentEvidence never applies a live deadline to saved proof. since
// is the issuer's clock claim; grade is its attestation claim, not an outside
// inspection of private hardware data. A nil receipt preserves these issuer
// facts and reports not_presented, never proof checked.
func VerifyEnrollmentEvidence(statement, receipt map[string]any, trust Trust) (EnrollmentEvidence, error) {
	var out EnrollmentEvidence
	e, err := checkEnrollmentStatement(statement, trust)
	if err != nil {
		return out, err
	}
	f := object(e, "enrollment")
	out = EnrollmentEvidence{Person: trust.Person, Credential: text(f, "credential"), Grade: text(f, "grade"), Since: number(f, "since"), ProofStatus: "not_presented"}
	if receipt != nil {
		if validate("receipt", receipt) != nil {
			return EnrollmentEvidence{}, refuse("enrollment_proof_invalid")
		}
		raw, err := decode(text(receipt, "request_bytes"))
		if err != nil {
			return EnrollmentEvidence{}, refuse("enrollment_proof_invalid")
		}
		request, err := Parse(raw)
		if err != nil || validate("request", request) != nil {
			return EnrollmentEvidence{}, refuse("enrollment_proof_invalid")
		}
		origin := text(object(object(receipt, "binding"), "binding"), "origin")
		checked, bh, _, err := creationAssertion(receipt, EnrollmentInput{Requester: object(request, "requester"), Origin: origin, Trust: &trust}, false)
		if err != nil {
			return EnrollmentEvidence{}, err
		}
		if err = matchEnrollmentConfirmation(e, receipt, checked, bh); err != nil {
			return EnrollmentEvidence{}, err
		}
		out.ProofStatus = "checked"
	}
	return out, nil
}
