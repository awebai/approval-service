package verify

import (
	"errors"
	"fmt"
	"testing"
)

func TestEnrollmentEvidenceRefusalsExposeTheirCodeWithoutChangingText(t *testing.T) {
	vector := seamCases(t, "later-enrollment")[0].(map[string]any)
	activation := object(vector, "activation")
	trust := *seamTrust(t, vector["trust"])
	valid := object(activation, "evidence")
	if _, err := VerifyEnrollmentEvidence(valid, nil, trust); err != nil {
		t.Fatalf("supported signed evidence: %v", err)
	}

	for _, test := range []struct {
		name string
		edit func(map[string]any)
		code RefusalCode
	}{
		{"unsupported_kind", func(e map[string]any) { object(e, "evidence")["kind"] = "future_enrollment" }, EnrollmentEvidenceUnsupported},
		{"invalid_body", func(e map[string]any) { delete(object(e, "evidence"), "enrollment") }, EnrollmentEvidenceInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, err := Canonical(valid)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			test.edit(changed)
			_, err = VerifyEnrollmentEvidence(changed, nil, trust)
			var refusal *RefusalError
			if !errors.As(fmt.Errorf("verify enrollment: %w", err), &refusal) || refusal.Code != test.code || err.Error() != string(test.code) {
				t.Fatalf("typed refusal: %v, want %q", err, test.code)
			}
			var service *ServiceError
			if errors.As(err, &service) {
				t.Fatal("pure verification refusal acquired HTTP status semantics")
			}
		})
	}
}

func TestHTTPServiceErrorDoesNotBecomeAVerifierRefusal(t *testing.T) {
	_, err := ReadAnswer("poll", map[string]any{"error": map[string]any{"code": "requester_invalid"}}, AnswerInput{Status: 403})
	var service *ServiceError
	if !errors.As(err, &service) || service.HTTPStatus != 403 || service.Code != "requester_invalid" {
		t.Fatalf("HTTP refusal lost its status/code: %v", err)
	}
	var pure *RefusalError
	if errors.As(err, &pure) {
		t.Fatal("HTTP refusal was classified as a pure verifier error")
	}
}
