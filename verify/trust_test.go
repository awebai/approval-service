package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

func TestSharedPublicTrustVectors(t *testing.T) {
	raw, err := os.ReadFile("../vectors/trust.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Cases []struct {
			ID                  string         `json:"id"`
			Chain               []any          `json:"chain"`
			Status              map[string]any `json:"status"`
			Authority           map[string]any `json:"namespace_authority"`
			Acquired            int64          `json:"acquired_at"`
			Age                 float64        `json:"age_seconds"`
			Now                 int64          `json:"now"`
			Person              string         `json:"person"`
			Key                 string         `json:"identity_key"`
			Organisation        string         `json:"organisation"`
			ExpectedIssuer      string         `json:"expected_issuer"`
			ExpectedIssuerKey   string         `json:"expected_issuer_key"`
			ExpectedCertificate string         `json:"expected_certificate"`
			Accept              bool           `json:"accept"`
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err = d.Decode(&file); err != nil {
		t.Fatal(err)
	}
	for _, c := range file.Cases {
		t.Run(c.ID, func(t *testing.T) {
			observation := PublicObservation{Status: c.Status, NamespaceAuthority: c.Authority, AcquiredAt: c.Acquired, AgeSeconds: &c.Age}
			tr, e := DeriveTrust(c.Chain, c.Person, c.Key, c.Organisation, observation, c.Now)
			if (e == nil) != c.Accept {
				t.Fatalf("accept=%v want %v: %v", e == nil, c.Accept, e)
			}
			if e == nil {
				if base64.RawURLEncoding.EncodeToString(tr.IssuerPublicKey) != c.ExpectedIssuerKey || tr.Issuer != c.ExpectedIssuer || tr.Certificate != c.ExpectedCertificate {
					t.Fatalf("incorrect issuer/certificate trust: %+v", tr)
				}
				if tr.Person != c.Person || tr.IdentityKey != c.Key || tr.Organisation != c.Organisation || len(tr.Certificate) != 71 || len(tr.IssuerPublicKey) != 32 || tr.ObservedAt != c.Acquired-int64(c.Age) {
					t.Fatalf("wrong checked trust: %+v", tr)
				}
				if _, err := DeriveTrust(c.Chain, c.Person, c.Key, c.Organisation, observation, c.Acquired+61); err == nil {
					t.Fatal("renewed original age")
				}
			}
		})
	}
}
