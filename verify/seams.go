package verify

// The portable seam is NOT public status acquisition or an effect authorizer.
// Callers acquire current admission/Trust independently and consume the enforcer
// nonce with their own transaction. No org key is stored or exported here.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/awebai/aw/awid"
)

func Commitment(kind string, value any) (string, error) {
	b, e := Canonical(value)
	if e != nil {
		return "", e
	}
	d := sha256.Sum256(append(domain(kind), b...))
	return "sha256:" + hex.EncodeToString(d[:]), nil
}
func equalValue(a, b any) bool {
	x, e := Canonical(a)
	y, f := Canonical(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func signature(key, sig string, preimage []byte) error {
	public, e := awid.ExtractPublicKey(key)
	if e != nil {
		return refuse("signature_invalid")
	}
	raw, e := decode(sig)
	if e != nil || len(raw) != 64 || !primePoint(raw[:32]) || !ed25519.Verify(public, preimage, raw) {
		return refuse("signature_invalid")
	}
	return nil
}
func preimage(kind string, value any) ([]byte, error) {
	b, e := Canonical(value)
	if e != nil {
		return nil, e
	}
	return append(domain(kind), b...), nil
}
func httpConfig() map[string]any { return wireSchema["x-http"].(map[string]any) }

type HTTPInput struct {
	Requester                     map[string]any
	Origin, Method, Path, Purpose string
	Now                           int64
}
type CheckedHTTP struct {
	Key       string
	Requester map[string]any
	IssuedAt  int64
	Preimage  []byte
	Body      map[string]any
}

func HTTPAuthorization(body []byte, private ed25519.PrivateKey, requester map[string]any, origin, purpose string, issuedAt int64) (string, error) {
	if len(private) != ed25519.PrivateKeySize {
		return "", refuse("requester_mismatch")
	}
	public, e := awid.ExtractPublicKey(text(requester, "key"))
	if e != nil || !bytes.Equal(public, private.Public().(ed25519.PublicKey)) {
		return "", refuse("requester_mismatch")
	}
	value, e := Parse(body)
	if e != nil {
		return "", e
	}
	b, e := Canonical(value)
	if e != nil {
		return "", e
	}
	digest := sha256.Sum256(b)
	path, ok := httpConfig()["routes"].(map[string]any)[purpose].(string)
	if !ok {
		return "", refuse("http_binding_mismatch")
	}
	proof := map[string]any{"version": json.Number("1"), "purpose": purpose, "requester": requester, "origin": origin, "method": "POST", "path": path, "issued_at": json.Number(fmt.Sprint(issuedAt)), "body_sha256": hex.EncodeToString(digest[:])}
	if e = validate("http_proof", proof); e != nil {
		return "", e
	}
	signed, e := preimage("http_request", proof)
	if e != nil {
		return "", e
	}
	packet := map[string]any{"proof": proof, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, signed))}
	raw, e := Canonical(packet)
	if e != nil {
		return "", e
	}
	return "Awsign " + base64.RawURLEncoding.EncodeToString(raw), nil
}
func CheckHTTP(authorization string, body []byte, in HTTPInput) (CheckedHTTP, error) {
	var out CheckedHTTP
	bad := func(code string) (CheckedHTTP, error) { return out, refuse(code) }
	if len(authorization) > int(httpConfig()["max_header_bytes"].(float64)) || !strings.HasPrefix(authorization, "Awsign ") {
		return bad("http_authorization_invalid")
	}
	raw, e := decode(strings.TrimPrefix(authorization, "Awsign "))
	if e != nil {
		return bad("http_invalid")
	}
	packet, e := Parse(raw)
	if e != nil || validate("http_authorization", packet) != nil {
		return bad("http_invalid")
	}
	b, e := Canonical(packet)
	if e != nil || !bytes.Equal(raw, b) {
		return bad("http_authorization_noncanonical")
	}
	p := object(packet, "proof")
	if !equalValue(p["requester"], in.Requester) {
		return bad("requester_mismatch")
	}
	if text(p, "origin") != in.Origin || text(p, "method") != in.Method || text(p, "path") != in.Path || text(p, "purpose") != in.Purpose {
		return bad("http_binding_mismatch")
	}
	if in.Method != "POST" || httpConfig()["routes"].(map[string]any)[in.Purpose] != in.Path {
		return bad("http_binding_mismatch")
	}
	age := in.Now - number(p, "issued_at")
	if age < 0 || age > int64(httpConfig()["freshness_seconds"].(float64)) {
		return bad("http_expired")
	}
	value, e := Parse(body)
	if e != nil {
		return bad("http_invalid")
	}
	b, e = Canonical(value)
	if e != nil {
		return bad("http_invalid")
	}
	digest := sha256.Sum256(b)
	if text(p, "body_sha256") != hex.EncodeToString(digest[:]) {
		return bad("http_body_mismatch")
	}
	signed, e := preimage("http_request", p)
	if e != nil {
		return bad("http_invalid")
	}
	if e = signature(text(in.Requester, "key"), text(packet, "signature"), signed); e != nil {
		return out, e
	}
	return CheckedHTTP{text(in.Requester, "key"), in.Requester, number(p, "issued_at"), signed, value}, nil
}

type EnrollmentInput struct {
	IssuerKey    string
	Requester    map[string]any
	Origin, RPID string
	Now          int64
	Trust        *Trust
}
type CheckedEnrollment struct {
	Person, Certificate, IdentityKey, State, Locator, BindingCommitment string
	Preimage                                                            []byte
}

func CheckEnrollmentIntent(signed map[string]any, in EnrollmentInput) (CheckedEnrollment, error) {
	var out CheckedEnrollment
	bad := func(code string) (CheckedEnrollment, error) { return out, refuse(code) }
	if validate("enrollment_intent", signed) != nil {
		return bad("enrollment_invalid")
	}
	b := object(signed, "intent")
	if !equalValue(b["requester"], in.Requester) {
		return bad("requester_mismatch")
	}
	if text(b, "origin") != in.Origin || text(b, "rp_id") != in.RPID || checkSite(in.Origin, in.RPID) != nil {
		return bad("origin_invalid")
	}
	if in.Now < number(b, "not_before") || in.Now >= number(b, "deadline") {
		return bad("enrollment_expired")
	}
	challenge, e := decode(text(b, "challenge"))
	if e != nil || len(challenge) != 32 {
		return bad("enrollment_challenge_invalid")
	}
	certificate := object(b, "pending_certificate")
	if e = awid.VerifyIDCertificate(certificate, in.IssuerKey); e != nil {
		return bad("enrollment_invalid")
	}
	c := object(certificate, "certificate")
	if text(c, "id") != text(b, "person") || text(c, "domain") != text(b, "organisation") || text(c, "kind") != "human" || text(c, "issuer_key") != in.IssuerKey {
		return bad("enrollment_certificate_mismatch")
	}
	if _, e = awid.ExtractPublicKey(text(b, "identity_key")); e != nil {
		return bad("enrollment_invalid")
	}
	signedBytes, e := preimage("enrollment_intent", b)
	if e != nil {
		return bad("enrollment_invalid")
	}
	if e = signature(in.IssuerKey, text(signed, "signature"), signedBytes); e != nil {
		return out, e
	}
	cid, e := awid.IDCertificateID(c)
	if e != nil {
		return bad("enrollment_invalid")
	}
	locator, e := Commitment("enrollment_locator", signed)
	if e != nil {
		return bad("enrollment_invalid")
	}
	return CheckedEnrollment{Person: text(b, "person"), Certificate: cid, IdentityKey: text(b, "identity_key"), State: "pending", Locator: locator, Preimage: signedBytes}, nil
}
func CheckActivation(value map[string]any, in EnrollmentInput) (CheckedEnrollment, error) {
	var out CheckedEnrollment
	bad := func(code string) (CheckedEnrollment, error) { return out, refuse(code) }
	if validate("enrollment_activation", value) != nil {
		return bad("activation_invalid")
	}
	pending, e := CheckEnrollmentIntent(object(value, "intent"), in)
	if e != nil {
		return out, e
	}
	trust := in.Trust
	if trust == nil || in.Now < trust.ObservedAt || in.Now-trust.ObservedAt > 60 {
		return bad("identity_unavailable")
	}
	if trust.Person != pending.Person || trust.Certificate != pending.Certificate || trust.IdentityKey != pending.IdentityKey || trust.Issuer != in.IssuerKey {
		return bad("enrollment_identity_mismatch")
	}
	receipt := object(value, "creation_receipt")
	raw, e := decode(text(receipt, "request_bytes"))
	if e != nil {
		return bad("activation_invalid")
	}
	r, e := Parse(raw)
	if e != nil || validate("request", r) != nil {
		return bad("activation_invalid")
	}
	if text(r, "purpose") != "enrollment_confirmation" {
		return bad("purpose_invalid")
	}
	if !equalValue(r["requester"], in.Requester) {
		return bad("requester_mismatch")
	}
	if in.Now < number(r, "not_before") || in.Now >= number(r, "deadline") {
		return bad("request_expired")
	}
	if !equalValue(receipt["binding"], value["binding"]) {
		return bad("binding_mismatch")
	}
	if e = CheckDefinition(r); e != nil {
		return out, e
	}
	checked, e := VerifyHistorical(receipt, r, *trust)
	if e != nil {
		return out, e
	}
	if checked.Origin != in.Origin {
		return bad("origin_invalid")
	}
	bh, e := Commitment("binding_commitment", value["binding"])
	if e != nil {
		return bad("activation_invalid")
	}
	act := object(r, "act")
	target, ok := act["target"].(map[string]any)
	if !ok || target["person"] != trust.Person || target["certificate"] != trust.Certificate || target["identity_key"] != trust.IdentityKey || target["binding_commitment"] != bh {
		return bad("creation_target_mismatch")
	}
	if !equalValue(value["id_chain"], receipt["id_chain"]) {
		return bad("identity_chain_mismatch")
	}
	chain := value["id_chain"].([]any)
	found := false
	intent := object(object(value, "intent"), "intent")
	for _, c := range chain {
		found = found || equalValue(c, intent["pending_certificate"])
	}
	if !found {
		return bad("identity_chain_mismatch")
	}
	evidence := object(value, "evidence")
	eb := object(evidence, "evidence")
	signedBytes, e := preimage("identity_evidence", eb)
	if e != nil {
		return bad("activation_invalid")
	}
	if e = signature(in.IssuerKey, text(evidence, "signature"), signedBytes); e != nil {
		return out, e
	}
	subject := map[string]any{"id": trust.Person, "certificate": trust.Certificate, "key": trust.IdentityKey}
	if !equalValue(eb["subject"], subject) || text(eb, "organisation") != trust.Organisation || text(eb, "issuer") != in.IssuerKey {
		return bad("evidence_subject_mismatch")
	}
	ch, e := Commitment("receipt_commitment", receipt)
	if e != nil {
		return bad("activation_invalid")
	}
	creation := map[string]any{"credential": checked.Credential, "grade": checked.Grade, "receipt_commitment": ch}
	if text(eb, "binding_commitment") != bh || !equalValue(eb["creation"], creation) {
		return bad("evidence_binding_mismatch")
	}
	binding := object(object(value, "binding"), "binding")
	if text(binding, "origin") != in.Origin || text(binding, "rp_id") != in.RPID {
		return bad("origin_invalid")
	}
	return CheckedEnrollment{Person: trust.Person, State: "active", BindingCommitment: bh}, nil
}
func ReadNeedsHuman(value map[string]any, requester map[string]any, origin string, now int64, status int64) (map[string]any, error) {
	if status != int64(wireSchema["x-enforcer"].(map[string]any)["needs_human_status"].(float64)) {
		return nil, refuse("http_status_invalid")
	}
	if validate("needs_human", value) != nil {
		return nil, refuse("needs_human_invalid")
	}
	if text(value, "approval_origin") != origin {
		return nil, refuse("origin_invalid")
	}
	raw, e := decode(text(value, "request_bytes"))
	if e != nil {
		return nil, e
	}
	r, e := Parse(raw)
	if e != nil || validate("request", r) != nil {
		return nil, refuse("needs_human_invalid")
	}
	if e = CheckDefinition(r); e != nil {
		return nil, e
	}
	b, e := Canonical(r)
	if e != nil || !bytes.Equal(raw, b) {
		return nil, refuse("request_mismatch")
	}
	if text(r, "purpose") != "act_approval" {
		return nil, refuse("purpose_invalid")
	}
	if !equalValue(r["requester"], requester) {
		return nil, refuse("requester_mismatch")
	}
	if now < number(r, "not_before") || now >= number(r, "deadline") {
		return nil, refuse("request_expired")
	}
	digest := sha256.Sum256(append(domain("request"), raw...))
	if text(value, "digest") != hex.EncodeToString(digest[:]) {
		return nil, refuse("request_digest_mismatch")
	}
	return r, nil
}
func CheckPresentation(value map[string]any, in EffectInputs, origin string) (CheckedApproval, error) {
	var out CheckedApproval
	if validate("presentation", value) != nil {
		return out, refuse("presentation_invalid")
	}
	raw, e := decode(text(value, "request_bytes"))
	want, f := Canonical(in.ExpectedRequest)
	if e != nil || f != nil || !bytes.Equal(raw, want) {
		return out, refuse("request_mismatch")
	}
	checked, e := VerifyForEffect(object(value, "receipt"), in)
	if e != nil {
		return out, e
	}
	if checked.Origin != origin {
		return out, refuse("origin_invalid")
	}
	return checked, nil
}

func MakeNeedsHuman(request map[string]any, origin string) (int, map[string]any, error) {
	if e := CheckDefinition(request); e != nil {
		return 0, nil, e
	}
	if text(request, "purpose") != "act_approval" {
		return 0, nil, refuse("purpose_invalid")
	}
	raw, e := Canonical(request)
	if e != nil {
		return 0, nil, e
	}
	d := sha256.Sum256(append(domain("request"), raw...))
	return int(wireSchema["x-enforcer"].(map[string]any)["needs_human_status"].(float64)), map[string]any{"version": json.Number("1"), "status": "needs_human", "approval_origin": origin, "request_bytes": base64.RawURLEncoding.EncodeToString(raw), "digest": hex.EncodeToString(d[:])}, nil
}
