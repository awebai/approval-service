package verify

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSignedClientDataMemberVectors(t *testing.T) {
	raw, err := os.ReadFile("../vectors/client-data-members.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []VectorCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != 7 {
		t.Fatalf("missing exact-member neighbors: %d", len(corpus.Cases))
	}
	for _, c := range corpus.Cases {
		t.Run(c.ID, func(t *testing.T) {
			_, err := VerifyVector(c)
			if (err == nil) != c.Accept {
				t.Fatalf("accepted=%v want %v: %v", err == nil, c.Accept, err)
			}
		})
	}
}
