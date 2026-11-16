package verify

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestHTTPInteractiveSignerPreservesFrozenPackets(t *testing.T) {
	for _, item := range seamCases(t, "requester-service") {
		c := item.(map[string]any)
		if !c["accept"].(bool) || text(c, "phase") == "answer" || text(c, "phase") == "enrollment-request" {
			continue
		}
		t.Run(text(c, "id"), func(t *testing.T) {
			body, _ := decode(text(c, "body"))
			seed, _ := decode(text(c, "test_signing_seed"))
			private := ed25519.NewKeyFromSeed(seed)
			calls := 0
			header, err := HTTPAuthorizationWithSigner(body, object(c, "expected_requester"), text(c, "origin"), text(c, "purpose"), number(c, "signed_at"), func(payload []byte, description string) (string, []byte, error) {
				calls++
				want, _ := decode(text(c, "expected_preimage"))
				if !bytes.Equal(payload, want) || description == "" {
					t.Fatal("different signing bytes or no prompt")
				}
				return text(c, "expected_requester_key"), ed25519.Sign(private, payload), nil
			})
			if err != nil || calls != 1 || header != text(c, "authorization") {
				t.Fatalf("header=%s calls=%d err=%v", header, calls, err)
			}
		})
	}
}

func TestHTTPInteractiveSignerCannotSubstituteKeyOrSignAfterRefusal(t *testing.T) {
	c := seamCases(t, "requester-service")[0].(map[string]any)
	body, _ := decode(text(c, "body"))
	seed, _ := decode(text(c, "test_signing_seed"))
	private := ed25519.NewKeyFromSeed(seed)
	declined := errors.New("person declined")
	header, err := HTTPAuthorizationWithSigner(body, object(c, "expected_requester"), text(c, "origin"), text(c, "purpose"), number(c, "signed_at"), func([]byte, string) (string, []byte, error) { return "", nil, declined })
	if !errors.Is(err, declined) || header != "" {
		t.Fatalf("decline returned %q %v", header, err)
	}
	header, err = HTTPAuthorizationWithSigner(body, object(c, "expected_requester"), text(c, "origin"), text(c, "purpose"), number(c, "signed_at"), func(payload []byte, _ string) (string, []byte, error) {
		return "another key", ed25519.Sign(private, payload), nil
	})
	if err == nil || err.Error() != "requester_mismatch" || header != "" {
		t.Fatalf("wrong signer returned %q %v", header, err)
	}
}
