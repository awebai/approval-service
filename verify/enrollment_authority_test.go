package verify

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestPublicEnrollmentAuthorityCandidates(t *testing.T) {
	raw, err := os.ReadFile("../vectors/enrollment-authority-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []map[string]any `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		t.Run(text(c, "id"), func(t *testing.T) {
			age, _ := c["age_seconds"].(json.Number).Float64()
			trust, err := DeriveTrust(c["chain"].([]any), text(c, "person"), text(c, "identity_key"), text(c, "organisation"), PublicObservation{Status: object(c, "status"), NamespaceAuthority: object(c, "namespace_authority"), AcquiredAt: number(c, "acquired_at"), AgeSeconds: &age}, number(c, "now"))
			if err != nil {
				t.Fatal(err)
			}
			secret, _ := decode(text(c, "nonce_key"))
			_, err = VerifyForEffect(object(c, "receipt"), EffectInputs{ExpectedRequest: object(c, "request"), Trust: trust, Now: number(c, "now"), RequiredGrade: "passkey_uv", Presenter: object(object(c, "request"), "requester"), NonceKeys: map[string][]byte{"k1": secret}})
			if (err == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v want=%v: %v", err == nil, c["accept"], err)
			}
			if expected, ok := c["expected_error"].(string); ok && (err == nil || err.Error() != expected) {
				t.Fatalf("refusal %v want %s", err, expected)
			}
		})
	}
}
