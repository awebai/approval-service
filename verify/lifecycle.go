package verify

// EnrollmentHistory is independently checked prior enrollment state. Neither it
// nor TransitionTrust is constructed by trusting a receipt's supplied keys.
// The issuer/enforcer owns eligibility and atomic effect/nonce consumption.
type EnrollmentHistory struct {
	Binding, Evidence map[string]any
	Trust             *Trust
}

func checkLifecycle(value map[string]any, in EnrollmentInput, newCreation map[string]any) error {
	p := in.Previous
	if p == nil || p.Trust == nil {
		return refuse("enrollment_previous_unavailable")
	}
	trust := p.Trust
	evidence := p.Evidence
	if supplied, ok := value["previous_evidence"].(map[string]any); ok {
		if evidence != nil && !equalValue(supplied, evidence) {
			return refuse("transition_before_mismatch")
		}
		evidence = supplied
	}
	if validate("binding", p.Binding) != nil || (evidence != nil && validate("creation_evidence", evidence) != nil) {
		return refuse("activation_invalid")
	}
	b := object(p.Binding, "binding")
	var eb map[string]any
	if evidence != nil {
		eb = object(evidence, "evidence")
	}
	subject := map[string]any{"id": trust.Person, "certificate": trust.Certificate, "key": trust.IdentityKey}
	if text(b, "person") != trust.Person || text(b, "organisation") != trust.Organisation || text(b, "identity_key") != trust.IdentityKey || text(b, "certificate") != trust.Certificate || text(b, "issuer") != trust.Issuer {
		return refuse("binding_mismatch")
	}
	raw, e := preimage("binding", b)
	if e != nil {
		return refuse("activation_invalid")
	}
	if e = signature(trust.Issuer, text(p.Binding, "signature"), raw); e != nil {
		return e
	}
	bh, e := Commitment("binding_commitment", p.Binding)
	if e != nil {
		return refuse("activation_invalid")
	}
	if evidence != nil {
		raw, e = preimage("identity_evidence", eb)
		if e != nil {
			return refuse("activation_invalid")
		}
		if e = signature(trust.Issuer, text(evidence, "signature"), raw); e != nil {
			return e
		}
		if !equalValue(eb["subject"], subject) || text(eb, "binding_commitment") != bh || text(eb, "organisation") != trust.Organisation || text(eb, "issuer") != trust.Issuer {
			return refuse("evidence_subject_mismatch")
		}
	}
	i := object(object(value, "intent"), "intent")
	afterB := object(object(value, "binding"), "binding")
	afterE := object(object(value, "evidence"), "evidence")
	transition, ok := afterE["transition"].(map[string]any)
	if !ok {
		return refuse("transition_mode_invalid")
	}
	before := map[string]any{"subject": subject, "binding_commitment": bh}
	if evidence == nil && text(transition, "mode") != "recreated" {
		return refuse("enrollment_previous_unavailable")
	}
	var eh any
	if evidence != nil {
		eh, e = Commitment("identity_evidence_commitment", evidence)
		if e != nil {
			return refuse("activation_invalid")
		}
	}
	if i["previous_binding_commitment"] != bh || !equalValue(transition["before"], before) || transition["previous_evidence_commitment"] != eh {
		return refuse("transition_before_mismatch")
	}
	if text(afterB, "person") != trust.Person || text(afterB, "organisation") != trust.Organisation || text(afterB, "identity_key") == trust.IdentityKey {
		return refuse("enrollment_identity_mismatch")
	}
	ch, e := Commitment("receipt_commitment", value["creation_receipt"])
	if e != nil {
		return refuse("activation_invalid")
	}
	if text(transition, "confirmation_receipt_commitment") != ch {
		return refuse("evidence_binding_mismatch")
	}
	mode := text(transition, "mode")
	if text(i, "purpose") == "enroll_person" {
		_, hasReceipt := value["transition_receipt"]
		if mode != "recreated" || transition["approval_receipt_commitment"] != nil || hasReceipt {
			return refuse("transition_mode_invalid")
		}
		if !equalValue(afterE["creation"], newCreation) {
			return refuse("evidence_binding_mismatch")
		}
		return nil
	}
	if mode != "unbroken" && mode != "assisted" {
		return refuse("transition_mode_invalid")
	}
	if !equalValue(afterE["creation"], eb["creation"]) {
		return refuse("creation_changed")
	}
	receipt, ok := value["transition_receipt"].(map[string]any)
	if !ok || in.TransitionTrust == nil {
		return refuse("transition_receipt_unavailable")
	}
	rh, e := Commitment("receipt_commitment", receipt)
	if e != nil {
		return refuse("activation_invalid")
	}
	if transition["approval_receipt_commitment"] != rh {
		return refuse("transition_receipt_mismatch")
	}
	requestRaw, e := decode(text(receipt, "request_bytes"))
	if e != nil {
		return refuse("activation_invalid")
	}
	request, e := Parse(requestRaw)
	if e != nil {
		return refuse("activation_invalid")
	}
	if e = CheckDefinition(request); e != nil {
		return e
	}
	checked, e := VerifyHistorical(receipt, request, *in.TransitionTrust)
	if e != nil {
		return e
	}
	same := checked.Person == trust.Person
	if (mode == "unbroken") != same {
		return refuse("transition_approver_mismatch")
	}
	if same && !equalValue(receipt["binding"], p.Binding) {
		return refuse("binding_mismatch")
	}
	afterTarget := map[string]any{"certificate": text(afterB, "certificate"), "identity_key": text(afterB, "identity_key"), "binding_commitment": text(afterE, "binding_commitment")}
	beforeTarget := map[string]any{"certificate": trust.Certificate, "identity_key": trust.IdentityKey, "binding_commitment": bh}
	target := map[string]any{"person": trust.Person, "before": beforeTarget, "after": afterTarget, "continuity": mode}
	if text(request, "purpose") != "act_approval" || text(object(request, "definition"), "id") != "human.enrollment.replace" || text(request, "organisation") != trust.Organisation || !equalValue(object(request, "act")["target"], target) {
		return refuse("transition_target_mismatch")
	}
	return nil
}
