package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSharedCanonicalAndKeyOrderVectors(t *testing.T) {
	raw, err := os.ReadFile("../vectors/shared-primitives/canonical-json-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	type canonicalCase struct {
		Name  string         `json:"name"`
		Value map[string]any `json:"value"`
		Hex   string         `json:"canonical_hex"`
	}
	var corpus struct {
		Cases []canonicalCase `json:"cases"`
		Order []canonicalCase `json:"code_point_key_order_cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	for _, c := range append(corpus.Cases, corpus.Order...) {
		t.Run(c.Name, func(t *testing.T) {
			got, err := Canonical(c.Value)
			if err != nil || hex.EncodeToString(got) != c.Hex {
				t.Fatalf("canonical mismatch: %x (%v)", got, err)
			}
		})
	}
}

func TestSharedEd25519VectorsThroughApprovalWireAdapter(t *testing.T) {
	raw, err := os.ReadFile("../vectors/shared-primitives/signature-primitives-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []struct {
			Name      string            `json:"name"`
			Payload   string            `json:"payload"`
			Signature string            `json:"signature"`
			Key       string            `json:"did_key"`
			Expected  map[string]string `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, c := range corpus.Cases {
		if c.Name != "raw-standard" && !strings.HasPrefix(c.Name, "ed25519-") {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			// The fixture's ordinary standard-base64 bytes enter approval's
			// canonical base64url codec; message text compatibility is separate.
			sig, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(c.Signature, "="))
			if err != nil {
				t.Fatal(err)
			}
			err = signature(c.Key, base64.RawURLEncoding.EncodeToString(sig), []byte(c.Payload))
			if (err == nil) != (c.Expected["go"] == "verified") {
				t.Fatalf("wrong signature outcome: %v", err)
			}
		})
	}
}
