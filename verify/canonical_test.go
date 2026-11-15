package verify

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedCanonicalVectors(t *testing.T) {
	raw, err := os.ReadFile("../vectors/canonical-json.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			ID           string `json:"id"`
			InputHex     string `json:"input_hex"`
			CanonicalHex string `json:"canonical_hex"`
			Refused      bool   `json:"refused"`
		} `json:"cases"`
	}
	if err = json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			input, _ := hex.DecodeString(c.InputHex)
			v, e := Parse(input)
			if c.Refused {
				if e == nil {
					t.Fatal("unsafe input accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			got, e := Canonical(v)
			if e != nil || hex.EncodeToString(got) != c.CanonicalHex {
				t.Fatalf("canonical mismatch %x (%v)", got, e)
			}
		})
	}
}
