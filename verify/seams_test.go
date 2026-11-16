package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
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
	cases := v["cases"].([]any)
	for _, value := range cases {
		c := value.(map[string]any)
		if !c["accept"].(bool) {
			if code, ok := c["expected_error"].(string); !ok || code == "" {
				t.Fatalf("refusing vector has no pinned code: %v", c["id"])
			}
		}
	}
	return cases
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
		if c["phase"] == "answer" || c["phase"] == "enrollment-request" {
			continue
		}
		t.Run(text(c, "id"), func(t *testing.T) {
			body, e := decode(text(c, "body"))
			if e != nil {
				t.Fatal(e)
			}
			checked, e := CheckHTTP(text(c, "authorization"), body, HTTPInput{Requester: object(c, "expected_requester"), Origin: text(c, "origin"), Method: text(c, "method"), Path: text(c, "path"), Purpose: text(c, "purpose"), Now: number(c, "now")})
			if (e == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v expected=%v: %v", e == nil, c["accept"], e)
			}
			if expected, ok := c["expected_error"].(string); ok && (e == nil || e.Error() != expected) {
				t.Fatalf("wrong refusal: %v want %s", e, expected)
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
		if c["phase"] == "answer" || c["phase"] == "enrollment-request" {
			continue
		}
		t.Run(text(c, "id"), func(t *testing.T) {
			in := EnrollmentInput{IssuerKey: text(c, "issuer_key"), Requester: object(c, "requester"), Origin: text(c, "origin"), RPID: text(c, "rp_id"), Now: number(c, "now"), Trust: seamTrust(t, c["trust"])}
			var checked CheckedEnrollment
			var e error
			if text(c, "phase") != "activation" {
				checked, e = CheckEnrollmentIntent(object(c, "intent"), in)
				if e == nil {
					want, _ := decode(text(c, "expected_intent_preimage"))
					if checked.Locator != text(c, "expected_locator") || !bytes.Equal(checked.Preimage, want) {
						t.Fatal("wrong intent bytes/locator")
					}
				}
			}
			if e == nil {
				if text(c, "phase") == "creation" {
					if presenter, ok := c["presenter"].(map[string]any); ok {
						in.Requester = presenter
					}
					secret, _ := decode(text(c, "nonce_key"))
					checked, e = CheckCreationProof(object(object(c, "activation"), "creation_receipt"), object(c, "intent"), in, map[string][]byte{"k1": secret})
				}
				if text(c, "phase") == "activation" {
					if presenter, ok := c["presenter"].(map[string]any); ok {
						in.Requester = presenter
					}
					if auth, ok := c["activation_authorization"].(string); ok {
						raw, err := Canonical(c["activation"])
						if err != nil {
							t.Fatal(err)
						}
						_, err = CheckHTTP(auth, raw, HTTPInput{Requester: in.Requester, Origin: in.Origin, Method: "POST", Path: "/v1/enrollments/activate", Purpose: "enrollment_activate", Now: in.Now})
						if err != nil {
							t.Fatalf("carrier signature did not verify: %v", err)
						}
					}
					checked, e = CheckActivation(object(c, "activation"), in)
				}
			}
			if (e == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v expected=%v: %v", e == nil, c["accept"], e)
			}
			if expected, ok := c["expected_error"].(string); ok && (e == nil || e.Error() != expected) {
				t.Fatalf("wrong refusal: %v want %s", e, expected)
			}
			if e == nil && (checked.Person != text(c, "expected_person") || checked.State != text(c, "expected_state")) {
				t.Fatal("wrong person or pending/active boundary")
			}
			if e == nil && text(c, "phase") == "creation" && (checked.Credential != text(c, "expected_credential") || checked.Grade != text(c, "expected_grade") || checked.Digest != text(c, "expected_digest")) {
				t.Fatal("wrong checked creation credential/grade/digest")
			}
		})
	}
}
func TestEnforcerRequesterSeam(t *testing.T) {
	for _, v := range seamCases(t, "enforcer-requester") {
		c := v.(map[string]any)
		if c["phase"] == "answer" || c["phase"] == "enrollment-request" {
			continue
		}
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
			if expected, ok := c["expected_error"].(string); ok && (e == nil || e.Error() != expected) {
				t.Fatalf("wrong refusal: %v want %s", e, expected)
			}
			if e == nil && digest != text(c, "expected_digest") {
				t.Fatal("wrong request digest")
			}
		})
	}
}

func TestPublishedDefinitionHashPins(t *testing.T) {
	raw, e := os.ReadFile("../vectors/definition-hashes-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	pins, e := Parse(raw)
	if e != nil {
		t.Fatal(e)
	}
	if len(pins) != len(wireSchema["x-act-definitions"].(map[string]any)) {
		t.Fatal("definition lacks literal versioned hash pin")
	}
	for key, expected := range pins {
		id, version, ok := strings.Cut(key, "@")
		if !ok {
			t.Fatal(key)
		}
		ref, e := DefinitionRef(id)
		if e != nil || text(ref, "sha256") != expected || ref["version"].(json.Number).String() != version {
			t.Fatalf("published definition changed: %s: %v", key, e)
		}
	}
}

func TestServiceAnswerVectors(t *testing.T) {
	for _, name := range []string{"requester-service", "issuer-service-enrollment", "enforcer-requester"} {
		for _, v := range seamCases(t, name) {
			c := v.(map[string]any)
			if c["phase"] != "answer" {
				continue
			}
			t.Run(text(c, "id"), func(t *testing.T) {
				raw, _ := decode(text(c, "answer"))
				var request []byte
				if c["request_bytes"] != nil {
					request, _ = decode(text(c, "request_bytes"))
				}
				var intent map[string]any
				if c["intent"] != nil {
					intent = object(c, "intent")
				}
				locator := ""
				if c["locator"] != nil {
					locator = text(c, "locator")
				}
				in := AnswerInput{Status: int(number(c, "response_status")), RequestBytes: request, Intent: intent, Locator: locator}
				answer, e := ReadAnswerJSON(text(c, "kind"), raw, in)
				if e == nil && text(c, "mode") == "assemble" {
					var receipt map[string]any
					receipt, e = AssembleReceipt(request, answer, in)
					if e == nil {
						actual, _ := Canonical(receipt)
						expected, _ := decode(text(c, "expected_receipt_bytes"))
						if !bytes.Equal(actual, expected) {
							t.Fatal("assembled receipt differs from frozen enforcer/issuer C")
						}
					}
				}
				if (e == nil) != c["accept"].(bool) {
					t.Fatalf("accept=%v want=%v: %v", e == nil, c["accept"], e)
				}
				if _, ok := c["expected_http_status"]; ok {
					serviceError, yes := e.(*ServiceError)
					if !yes || serviceError.HTTPStatus != int(number(c, "expected_http_status")) {
						t.Fatal("lost actual HTTP status")
					}
				}
				if !c["accept"].(bool) {
					if e == nil || e.Error() != text(c, "expected_error") {
						t.Fatalf("wrong code: %v want %s", e, text(c, "expected_error"))
					}
				}
			})
		}
	}
}
func TestEnrollmentRequestBodies(t *testing.T) {
	for _, v := range seamCases(t, "issuer-service-enrollment") {
		c := v.(map[string]any)
		if c["phase"] != "enrollment-request" {
			continue
		}
		t.Run(text(c, "id"), func(t *testing.T) {
			checked, e := ReadEnrollmentRequest(text(c, "kind"), object(c, "body"), object(c, "intent"), EnrollmentInput{IssuerKey: text(c, "issuer_key"), Requester: object(c, "requester"), Origin: text(c, "origin"), RPID: text(c, "rp_id"), Now: number(c, "now")})
			if (e == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v want=%v: %v", e == nil, c["accept"], e)
			}
			if !c["accept"].(bool) && (e == nil || e.Error() != text(c, "expected_error")) {
				t.Fatalf("wrong code: %v", e)
			}
			if e == nil && (checked.Person != text(c, "expected_person") || checked.State != "pending") {
				t.Fatal("wrong enrollment state")
			}
		})
	}
}
