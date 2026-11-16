package verify

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
)

func seamCases(t *testing.T, name string) []any {
	t.Helper()
	raw, e := os.ReadFile("../vectors/" + name + "-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	v, e := Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	return v["cases"].([]any)
}
func seamTrust(t *testing.T, v any) *Trust {
	t.Helper()
	if v == nil {
		return nil
	}
	m := v.(map[string]any)
	raw, e := decode(text(m, "issuer_public_key"))
	if e != nil {
		t.Fatal(e)
	}
	return &Trust{Person: text(m, "person"), Organisation: text(m, "organisation"), IdentityKey: text(m, "identity_key"), Certificate: text(m, "certificate"), Issuer: text(m, "issuer"), IssuerPublicKey: raw, ObservedAt: number(m, "observed_at")}
}
func TestRequesterServiceSeam(t *testing.T) {
	for _, v := range seamCases(t, "requester-service") {
		c := v.(map[string]any)
		t.Run(text(c, "id"), func(t *testing.T) {
			body, e := decode(text(c, "body"))
			if e != nil {
				t.Fatal(e)
			}
			checked, e := CheckHTTP(text(c, "authorization"), body, HTTPInput{Requester: object(c, "expected_requester"), Origin: text(c, "origin"), Method: text(c, "method"), Path: text(c, "path"), Purpose: text(c, "purpose"), Now: number(c, "now")})
			if (e == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v expected=%v: %v", e == nil, c["accept"], e)
			}
			if e == nil {
				seed, _ := decode(text(c, "test_signing_seed"))
				produced, err := HTTPAuthorization(body, ed25519.NewKeyFromSeed(seed), object(c, "expected_requester"), text(c, "origin"), text(c, "purpose"), number(c, "signed_at"))
				if err != nil || produced != text(c, "authorization") {
					t.Fatalf("producer differs: %v", err)
				}
				want, _ := decode(text(c, "expected_preimage"))
				if checked.Key != text(c, "expected_requester_key") || !bytes.Equal(checked.Preimage, want) {
					t.Fatal("wrong signed bytes or key")
				}
			}
		})
	}
}
func TestIssuerEnrollmentSeam(t *testing.T) {
	for _, v := range seamCases(t, "issuer-service-enrollment") {
		c := v.(map[string]any)
		t.Run(text(c, "id"), func(t *testing.T) {
			in := EnrollmentInput{IssuerKey: text(c, "issuer_key"), Requester: object(c, "requester"), Origin: text(c, "origin"), RPID: text(c, "rp_id"), Now: number(c, "now"), Trust: seamTrust(t, c["trust"])}
			checked, e := CheckEnrollmentIntent(object(c, "intent"), in)
			if e == nil {
				want, _ := decode(text(c, "expected_intent_preimage"))
				if checked.Locator != text(c, "expected_locator") || !bytes.Equal(checked.Preimage, want) {
					t.Fatal("wrong intent bytes/locator")
				}
				if text(c, "phase") == "activation" {
					checked, e = CheckActivation(object(c, "activation"), in)
				}
			}
			if (e == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v expected=%v: %v", e == nil, c["accept"], e)
			}
			if e == nil && (checked.Person != text(c, "expected_person") || checked.State != text(c, "expected_state")) {
				t.Fatal("wrong person or pending/active boundary")
			}
		})
	}
}
func TestEnforcerRequesterSeam(t *testing.T) {
	for _, v := range seamCases(t, "enforcer-requester") {
		c := v.(map[string]any)
		t.Run(text(c, "id"), func(t *testing.T) {
			var digest string
			var e error
			if text(c, "phase") == "needs_human" {
				var r map[string]any
				r, e = ReadNeedsHuman(object(c, "needs_human"), object(c, "presenter"), text(c, "origin"), number(c, "now"), number(c, "http_status"))
				if e == nil {
					if !equalValue(r, c["request"]) {
						t.Fatal("changed R")
					}
					status, body, err := MakeNeedsHuman(r, text(c, "origin"))
					if err != nil || int64(status) != number(c, "http_status") || !equalValue(body, c["needs_human"]) {
						t.Fatal("enforcer producer differs")
					}
					digest = text(object(c, "needs_human"), "digest")
				}
			} else {
				secret, _ := decode(text(c, "nonce_key"))
				var checked CheckedApproval
				checked, e = CheckPresentation(object(c, "presentation"), EffectInputs{ExpectedRequest: object(c, "request"), Trust: *seamTrust(t, c["trust"]), Now: number(c, "now"), RequiredGrade: text(c, "required_grade"), Presenter: object(c, "presenter"), NonceKeys: map[string][]byte{"k1": secret}}, text(c, "origin"))
				digest = checked.Digest
			}
			if (e == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v expected=%v: %v", e == nil, c["accept"], e)
			}
			if e == nil && digest != text(c, "expected_digest") {
				t.Fatal("wrong request digest")
			}
		})
	}
}
