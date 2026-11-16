package verify

// Public observations are trusted acquisition inputs, NEVER receipt fields.
// All ID certificate/log/DNS semantics remain in the existing AWID library.
import (
	"context"
	"math"
	"time"

	"github.com/awebai/aw/awid"
)

type PublicObservation struct {
	Status             map[string]any
	NamespaceAuthority map[string]any
	AcquiredAt         int64
	AgeSeconds         *float64
}

func DeriveTrust(chain []any, person, identityKey, organisation string, observation PublicObservation, now int64) (Trust, error) {
	bad := func(code string) (Trust, error) { return Trust{}, refuse(code) }
	if now < 0 || observation.AcquiredAt < 0 || now < observation.AcquiredAt || observation.AgeSeconds == nil {
		return bad("status_unavailable")
	}
	age := *observation.AgeSeconds
	if math.IsNaN(age) || math.IsInf(age, 0) || age < 0 || age > 60 || now-observation.AcquiredAt > 60 {
		return bad("status_unavailable")
	}
	totalAge := age + float64(now-observation.AcquiredAt)
	if totalAge > 60 {
		return bad("status_unavailable")
	}
	if len(chain) == 0 {
		return bad("identity_chain_required")
	}
	bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": chain}
	evidence := &awid.IDChainEvidence{Status: observation.Status, NamespaceAuthority: observation.NamespaceAuthority, AgeSeconds: &totalAge}
	checked := awid.VerifyIDChain(bundle, awid.IDChainSubject{ID: person, DIDKey: identityKey}, evidence, organisation)
	if checked.IdentityValid == nil || !*checked.IdentityValid {
		return bad("identity_" + checked.Reason)
	}
	if checked.Kind == nil || *checked.Kind != "human" || checked.HumanID == nil || *checked.HumanID != person {
		return bad("approver_not_person")
	}
	// Successful VerifyIDChain has validated all the objects read below.
	signed, ok := chain[len(chain)-1].(map[string]any)
	if !ok {
		return bad("identity_trust_invalid")
	}
	certificate := object(signed, "certificate")
	parent := object(certificate, "parent")
	issuer := ""
	if text(parent, "kind") == "namespace" {
		epochs, _ := object(observation.Status, "namespace")["epochs"].([]any)
		if len(epochs) == 0 {
			return bad("identity_trust_invalid")
		}
		row, ok := epochs[len(epochs)-1].(map[string]any)
		if !ok {
			return bad("identity_trust_invalid")
		}
		issuer = text(row, "did_key")
	} else {
		parentID := text(parent, "id")
		if len(parentID) >= 8 && parentID[:8] == "did:key:" {
			issuer = parentID
		} else {
			rows, _ := observation.Status["identities"].([]any)
			for _, v := range rows {
				row, ok := v.(map[string]any)
				if !ok {
					continue
				}
				if text(row, "id") != parentID {
					continue
				}
				history, _ := row["key_history"].([]any)
				if len(history) == 0 {
					continue
				}
				last, ok := history[len(history)-1].(map[string]any)
				if !ok {
					continue
				}
				issuer = text(object(last, "entry"), "new_did_key")
				break
			}
		}
	}
	key, err := awid.ExtractPublicKey(issuer)
	if err != nil {
		return bad("identity_trust_invalid")
	}
	digest, err := awid.IDCertificateID(certificate)
	if err != nil {
		return bad("identity_trust_invalid")
	}
	observedAt := observation.AcquiredAt - int64(math.Ceil(age))
	if observedAt < 0 {
		return bad("status_unavailable")
	}
	return Trust{Person: person, Organisation: organisation, IdentityKey: identityKey, Certificate: digest, Issuer: issuer, IssuerPublicKey: key, ObservedAt: observedAt}, nil
}

// ReadTrust uses the configured SDK public resolver and its original cache age.
// No status URL, DNS authority or cache timestamp is accepted from the receipt.
func ReadTrust(ctx context.Context, client *awid.IDStatusClient, chain []any, person, identityKey, organisation string) (Trust, error) {
	if client == nil {
		return Trust{}, refuse("status_unavailable")
	}
	bundle := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": chain}
	evidence := client.IDChainEvidence(ctx, bundle, awid.IDChainSubject{ID: person, DIDKey: identityKey}, organisation)
	acquired := time.Now().Unix()
	if evidence == nil {
		return Trust{}, refuse("status_unavailable")
	}
	return DeriveTrust(chain, person, identityKey, organisation, PublicObservation{Status: evidence.Status, NamespaceAuthority: evidence.NamespaceAuthority, AcquiredAt: acquired, AgeSeconds: evidence.AgeSeconds}, acquired)
}
