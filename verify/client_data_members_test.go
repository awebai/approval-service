package verify

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSignedClientDataMemberVectors(t *testing.T) {
	checkSignedClientDataVectors(t, "client-data-members.json", 7)
}

func TestSignedClientDataEOFAfterTheCompleteRawDocument(t *testing.T) {
	checkSignedClientDataVectors(t, "client-data-eof.json", 3)
}

func checkSignedClientDataVectors(t *testing.T, name string, expectedCount int) {
	t.Helper()
	raw, err := os.ReadFile("../vectors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []VectorCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Cases) != expectedCount {
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
