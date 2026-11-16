package verify

import "testing"

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
