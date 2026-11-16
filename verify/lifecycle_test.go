package verify

import "testing"

func TestLifecycleSeam(t *testing.T) {
	for _, v := range seamCases(t, "enrollment-lifecycle") {
		c := v.(map[string]any)
		t.Run(text(c, "id"), func(t *testing.T) {
			p := object(c, "previous")
			in := EnrollmentInput{IssuerKey: text(c, "issuer_key"), Requester: object(c, "requester"), Origin: text(c, "origin"), RPID: text(c, "rp_id"), Now: number(c, "now"), Trust: seamTrust(t, c["trust"]), Previous: &EnrollmentHistory{Binding: object(p, "binding"), Evidence: object(p, "evidence"), Trust: seamTrust(t, p["trust"])}, TransitionTrust: seamTrust(t, c["transition_trust"])}
			checked, e := CheckActivation(object(c, "activation"), in)
			if (e == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v expected=%v: %v", e == nil, c["accept"], e)
			}
			if expected, ok := c["expected_error"].(string); ok && (e == nil || e.Error() != expected) {
				t.Fatalf("wrong refusal %v want %s", e, expected)
			}
			if e == nil && checked.State != "active" {
				t.Fatal("not active")
			}
		})
	}
}
