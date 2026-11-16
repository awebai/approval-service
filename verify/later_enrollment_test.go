package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

func TestLaterEnrollment(t *testing.T) {
	for _, item := range seamCases(t, "later-enrollment") {
		c := item.(map[string]any)
		t.Run(text(c, "id"), func(t *testing.T) {
			got, err := CheckActivation(object(c, "activation"), EnrollmentInput{IssuerKey: text(c, "issuer_key"), Requester: object(c, "requester"), Origin: text(c, "origin"), RPID: text(c, "rp_id"), Now: number(c, "now"), Trust: seamTrust(t, c["trust"])})
			if (err == nil) != c["accept"].(bool) {
				t.Fatalf("accepted=%v want=%v: %v", err == nil, c["accept"], err)
			}
			if want, ok := c["expected_error"].(string); ok && (err == nil || err.Error() != want) {
				t.Fatalf("code=%v want=%s", err, want)
			}
			if err == nil && got.State != "active" {
				t.Fatal("not active")
			}
		})
	}
}

func TestLaterStatementOptionalProofAndDefinition(t *testing.T) {
	c := seamCases(t, "later-enrollment")[0].(map[string]any)
	a := object(c, "activation")
	trust := *seamTrust(t, c["trust"])
	claimed, err := VerifyEnrollmentEvidence(object(a, "evidence"), nil, trust)
	if err != nil || claimed.ProofStatus != "not_presented" {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	checked, err := VerifyEnrollmentEvidence(object(a, "evidence"), object(a, "confirmation_receipt"), trust)
	if err != nil || checked.ProofStatus != "checked" || checked.Grade != "passkey_uv" {
		t.Fatalf("proof: %+v %v", checked, err)
	}
	definition, err := StatementDefinition("human_enrolled_later")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Canonical(definition)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	pinsRaw, err := os.ReadFile("../vectors/statement-hashes-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	pins, err := Parse(pinsRaw)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(sum[:]) != text(pins, "human.enrolled_later@1") {
		t.Fatal("statement definition changed under its version")
	}
}
