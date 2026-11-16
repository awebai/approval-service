package verify

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSharedReceiptVectors(t *testing.T) {
	raw, e := os.ReadFile("../vectors/receipts.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Cases []VectorCase `json:"cases"`
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	if len(f.Cases) != 37 {
		t.Fatalf("missing vectors: %d", len(f.Cases))
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			_, e := VerifyVector(c)
			if (e == nil) != c.Accept {
				t.Fatalf("accepted=%v want %v: %v", e == nil, c.Accept, e)
			}
		})
	}
}

type VectorCase struct {
	ID      string          `json:"id"`
	Receipt json.RawMessage `json:"receipt"`
	Request json.RawMessage `json:"request"`
	Trust   struct {
		Person       string `json:"person"`
		Organisation string `json:"organisation"`
		IdentityKey  string `json:"identity_key"`
		Certificate  string `json:"certificate"`
		Issuer       string `json:"issuer"`
		PublicKey    string `json:"issuer_public_key"`
		ObservedAt   int64  `json:"observed_at"`
	} `json:"trust"`
	NonceKey      string          `json:"nonce_key"`
	Now           int64           `json:"now"`
	RequiredGrade string          `json:"required_grade"`
	Presenter     json.RawMessage `json:"presenter"`
	Accept        bool            `json:"accept"`
}

func VerifyVector(c VectorCase) (CheckedApproval, error) {
	receipt, e := Parse(c.Receipt)
	if e != nil {
		return CheckedApproval{}, e
	}
	request, e := Parse(c.Request)
	if e != nil {
		return CheckedApproval{}, e
	}
	presenter, e := Parse(c.Presenter)
	if e != nil {
		return CheckedApproval{}, e
	}
	key, e := decode(c.Trust.PublicKey)
	if e != nil {
		return CheckedApproval{}, e
	}
	secret, e := decode(c.NonceKey)
	if e != nil {
		return CheckedApproval{}, e
	}
	trust := Trust{Person: c.Trust.Person, Organisation: c.Trust.Organisation, IdentityKey: c.Trust.IdentityKey, Certificate: c.Trust.Certificate, Issuer: c.Trust.Issuer, IssuerPublicKey: key, ObservedAt: c.Trust.ObservedAt}
	return VerifyForEffect(receipt, EffectInputs{ExpectedRequest: request, Trust: trust, Now: c.Now, RequiredGrade: c.RequiredGrade, Presenter: presenter, NonceKeys: map[string][]byte{"k1": secret}})
}
