package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

type ServiceError struct {
	Code       string
	HTTPStatus int
}

func (e *ServiceError) Error() string { return e.Code }

type AnswerInput struct {
	Status       int
	RequestBytes []byte
	Intent       map[string]any
	Locator      string
}

func ReadAnswer(kind string, body map[string]any, in AnswerInput) (map[string]any, error) {
	bad := func(code string) (map[string]any, error) { return nil, refuse(code) }
	if in.Status >= 400 {
		if validate("service_error", body) != nil {
			return bad("service_response_invalid")
		}
		return nil, &ServiceError{text(object(body, "error"), "code"), in.Status}
	}
	statuses, ok := wireSchema["x-answer-status"].(map[string]any)[kind].([]any)
	if !ok {
		return bad("service_response_invalid")
	}
	allowed := false
	for _, v := range statuses {
		allowed = allowed || int(v.(float64)) == in.Status
	}
	if !allowed || validate(kind+"_answer", body) != nil {
		return bad("service_response_invalid")
	}
	if in.Locator != "" && text(body, "locator") != in.Locator {
		return bad("locator_mismatch")
	}
	var r map[string]any
	if kind == "submit" || kind == "poll" || kind == "cancel" || kind == "enrollment_confirm" {
		if in.RequestBytes == nil {
			return bad("request_mismatch")
		}
		var e error
		r, e = Parse(in.RequestBytes)
		if e != nil || validate("request", r) != nil {
			return bad("service_response_invalid")
		}
		raw, e := Canonical(r)
		if e != nil || !bytes.Equal(raw, in.RequestBytes) {
			return bad("request_mismatch")
		}
		h := sha256.Sum256(append(domain("request"), raw...))
		if text(body, "digest") != hex.EncodeToString(h[:]) {
			return bad("request_digest_mismatch")
		}
		if number(body, "deadline") != number(r, "deadline") {
			return bad("deadline_mismatch")
		}
		expected := "act_approval"
		if kind == "enrollment_confirm" {
			expected = "enrollment_confirmation"
		}
		if text(r, "purpose") != expected {
			return bad("purpose_invalid")
		}
	}
	if len(kind) > 11 && kind[:11] == "enrollment_" {
		if in.Intent == nil || validate("enrollment_intent", in.Intent) != nil {
			return bad("service_response_invalid")
		}
		loc, e := Commitment("enrollment_locator", in.Intent)
		if e != nil || text(body, "locator") != loc {
			return bad("locator_mismatch")
		}
		i := object(in.Intent, "intent")
		if kind == "enrollment_confirm" && (text(r, "approver") != text(i, "person") || text(r, "organisation") != text(i, "organisation") || !equalValue(r["requester"], i["requester"]) || number(r, "not_before") < number(i, "not_before") || number(r, "deadline") > number(i, "deadline")) {
			return bad("enrollment_intent_mismatch")
		}
		if kind == "enrollment_activate" {
			if text(body, "person") != text(i, "person") {
				return bad("person_mismatch")
			}
		} else if kind != "enrollment_confirm" && number(body, "deadline") != number(i, "deadline") {
			return bad("deadline_mismatch")
		}
		if kind == "enrollment_start" {
			p := object(body, "public_key")
			if text(p, "challenge") != text(i, "challenge") || text(object(p, "rp"), "id") != text(i, "rp_id") {
				return bad("enrollment_challenge_invalid")
			}
			u := object(p, "user")
			handle, e := decode(text(u, "id"))
			if e != nil || len(handle) != 32 || text(u, "name") != text(i, "person") || text(u, "displayName") != text(i, "person") {
				return bad("enrollment_user_invalid")
			}
			props := wireSchema["$defs"].(map[string]any)["credential"].(map[string]any)["properties"].(map[string]any)
			algs := props["algorithm"].(map[string]any)["enum"].([]any)
			expected := []any{}
			for _, a := range algs {
				expected = append(expected, map[string]any{"type": "public-key", "alg": int64(a.(float64))})
			}
			if !equalValue(p["pubKeyCredParams"], expected) {
				return bad("service_response_invalid")
			}
		}
	}
	return body, nil
}
func AssembleReceipt(requestBytes []byte, answer map[string]any, in AnswerInput) (map[string]any, error) {
	in.RequestBytes = requestBytes
	kind := "poll"
	if in.Intent != nil {
		kind = "enrollment_confirm"
	}
	if _, e := ReadAnswer(kind, answer, in); e != nil {
		return nil, e
	}
	state := text(answer, "state")
	if state != "approved" {
		code := map[string]string{"pending": "approval_pending", "denied": "approval_denied", "cancelled": "approval_cancelled", "expired": "request_expired"}[state]
		return nil, refuse(code)
	}
	if answer["approval"] == nil {
		return nil, refuse("receipt_unavailable")
	}
	bundle := object(answer, "approval")
	out := map[string]any{"version": json.Number("1"), "request_bytes": base64.RawURLEncoding.EncodeToString(requestBytes), "assertion": bundle["assertion"], "binding": bundle["binding"], "id_chain": bundle["id_chain"]}
	if validate("receipt", out) != nil {
		return nil, refuse("service_response_invalid")
	}
	return out, nil
}

func ReadAnswerJSON(kind string, raw []byte, in AnswerInput) (map[string]any, error) {
	body, e := Parse(raw)
	if e != nil {
		return nil, refuse("service_response_invalid")
	}
	return ReadAnswer(kind, body, in)
}
func ReadEnrollmentRequest(kind string, body, intent map[string]any, in EnrollmentInput) (CheckedEnrollment, error) {
	var out CheckedEnrollment
	bad := func(code string) (CheckedEnrollment, error) { return out, refuse(code) }
	if kind != "enrollment_material" && kind != "enrollment_confirm" {
		return bad("enrollment_request_invalid")
	}
	if validate(kind+"_request", body) != nil {
		return bad("enrollment_request_invalid")
	}
	if !equalValue(body["intent"], intent) {
		return bad("enrollment_intent_mismatch")
	}
	pending, e := CheckEnrollmentIntent(intent, in)
	if e != nil {
		return out, e
	}
	if kind == "enrollment_material" {
		return pending, nil
	}
	if kind != "enrollment_confirm" {
		return bad("enrollment_request_invalid")
	}
	signed := object(body, "binding")
	b := object(signed, "binding")
	i := object(intent, "intent")
	if text(b, "person") != pending.Person || text(b, "organisation") != text(i, "organisation") || text(b, "certificate") != pending.Certificate || text(b, "identity_key") != pending.IdentityKey || text(b, "issuer") != in.IssuerKey || text(b, "origin") != in.Origin || text(b, "rp_id") != in.RPID {
		return bad("binding_mismatch")
	}
	raw, e := preimage("binding", b)
	if e != nil {
		return bad("enrollment_request_invalid")
	}
	if e = signature(in.IssuerKey, text(signed, "signature"), raw); e != nil {
		return out, e
	}
	ids := map[string]bool{}
	keys := map[string]bool{}
	for _, v := range b["credentials"].([]any) {
		c := v.(map[string]any)
		key, e := decode(text(c, "key"))
		if e != nil {
			return bad("enrollment_request_invalid")
		}
		if _, e = credentialKey(key, number(c, "algorithm")); e != nil {
			return out, e
		}
		if ids[text(c, "id")] || keys[string(key)] {
			return bad("credential_key_invalid")
		}
		ids[text(c, "id")] = true
		keys[string(key)] = true
	}
	raw, e = decode(text(body, "request_bytes"))
	if e != nil {
		return bad("enrollment_request_invalid")
	}
	r, e := Parse(raw)
	if e != nil {
		return bad("enrollment_request_invalid")
	}
	if e = CheckDefinition(r); e != nil {
		return out, e
	}
	want, e := Canonical(r)
	if e != nil || !bytes.Equal(raw, want) {
		return bad("request_mismatch")
	}
	if text(r, "purpose") != "enrollment_confirmation" {
		return bad("purpose_invalid")
	}
	if !equalValue(r["requester"], in.Requester) {
		return bad("requester_mismatch")
	}
	if text(r, "approver") != text(i, "person") || text(r, "organisation") != text(i, "organisation") {
		return bad("person_mismatch")
	}
	if number(r, "not_before") < number(i, "not_before") || number(r, "not_before") > in.Now || number(r, "deadline") <= in.Now || number(r, "deadline") > number(i, "deadline") {
		return bad("request_expired")
	}
	bh, e := Commitment("binding_commitment", signed)
	if e != nil {
		return bad("enrollment_request_invalid")
	}
	expected := map[string]any{"person": pending.Person, "certificate": pending.Certificate, "identity_key": pending.IdentityKey, "binding_commitment": bh}
	if !equalValue(object(r, "act")["target"], expected) {
		return bad("creation_target_mismatch")
	}
	h := sha256.Sum256(append(domain("request"), raw...))
	pending.Digest = hex.EncodeToString(h[:])
	return pending, nil
}
