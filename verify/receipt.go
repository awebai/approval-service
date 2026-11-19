package verify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"unicode/utf8"

	"filippo.io/edwards25519"
	"github.com/awebai/aw/awid"
	"github.com/fxamacker/cbor/v2"
)

type Trust struct {
	Person, Organisation, IdentityKey, Certificate, Issuer string
	IssuerPublicKey                                        []byte
	ObservedAt                                             int64
	NamespaceIssuer                                        string
}
type CheckedApproval struct {
	Person, IdentityKey, Credential, Grade, Digest, Origin string
	Deadline                                               int64
}
type EffectInputs struct {
	ExpectedRequest map[string]any
	Trust           Trust
	Now             int64
	RequiredGrade   string
	Presenter       map[string]any
	NonceKeys       map[string][]byte
}

func decode(s string) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) == 0 || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, refuse("invalid_encoding")
	}
	return b, nil
}
func object(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }
func text(m map[string]any, k string) string           { return m[k].(string) }
func number(m map[string]any, k string) int64          { n, _ := m[k].(json.Number).Int64(); return n }

// Nonidentity canonical prime subgroup check extracted from aweb's ID verifier.
func primePoint(raw []byte) bool {
	p, e := new(edwards25519.Point).SetBytes(raw)
	if e != nil || !bytes.Equal(p.Bytes(), raw) || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return false
	}
	eight := [32]byte{8}
	s, _ := new(edwards25519.Scalar).SetCanonicalBytes(eight[:])
	inv := new(edwards25519.Scalar).Invert(s)
	q := new(edwards25519.Point).MultByCofactor(p)
	return q.ScalarMult(inv, q).Equal(p) == 1
}

var coseMode cbor.DecMode

func init() {
	var e error
	coseMode, e = (cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: int(wireSchema["x-cbor-limits"].(map[string]any)["max_depth"].(float64)), MaxMapPairs: int(wireSchema["x-cbor-limits"].(map[string]any)["max_map_pairs"].(float64)), MaxArrayElements: int(wireSchema["x-cbor-limits"].(map[string]any)["max_array_elements"].(float64)), TagsMd: cbor.TagsForbidden}).DecMode()
	if e != nil {
		panic(e)
	}
}
func cInt(v any) int64 {
	switch n := v.(type) {
	case uint64:
		if n <= 1<<63-1 {
			return int64(n)
		}
	case int64:
		return n
	}
	return 1 << 62
}
func credentialKey(raw []byte, algorithm int64) (crypto.PublicKey, error) {
	k := map[int64]any{}
	if e := coseMode.Unmarshal(raw, &k); e != nil {
		return nil, refuse("credential_key_invalid")
	}
	if cInt(k[3]) != algorithm {
		return nil, refuse("credential_key_invalid")
	}
	allowed := map[int64]bool{-1: true, -2: true}
	if algorithm == -7 {
		allowed[-3] = true
	}
	for label := range k {
		if label < 0 && !allowed[label] {
			return nil, refuse("credential_key_invalid")
		}
	}
	switch algorithm {
	case -7:
		x, xok := k[-2].([]byte)
		y, yok := k[-3].([]byte)
		if cInt(k[1]) != 2 || cInt(k[-1]) != 1 || !xok || !yok || len(x) != 32 || len(y) != 32 {
			return nil, refuse("credential_key_invalid")
		}
		p := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !p.Curve.IsOnCurve(p.X, p.Y) {
			return nil, refuse("credential_key_invalid")
		}
		return p, nil
	case -8:
		x, ok := k[-2].([]byte)
		if cInt(k[1]) != 1 || cInt(k[-1]) != 6 || !ok || !primePoint(x) {
			return nil, refuse("credential_key_invalid")
		}
		return ed25519.PublicKey(x), nil
	case -257:
		n, nok := k[-1].([]byte)
		e, eok := k[-2].([]byte)
		if cInt(k[1]) != 3 || !nok || !eok || len(n) == 0 || n[0] == 0 || !bytes.Equal(e, []byte{1, 0, 1}) {
			return nil, refuse("credential_key_invalid")
		}
		p := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}
		if p.N.BitLen() < 2048 || p.N.BitLen() > 8192 {
			return nil, refuse("credential_key_invalid")
		}
		return p, nil
	}
	return nil, refuse("credential_key_invalid")
}
func rawVerify(receipt, expected map[string]any, trust Trust) (map[string]any, CheckedApproval, error) {
	var out CheckedApproval
	fail := func(code RefusalCode) (map[string]any, CheckedApproval, error) { return nil, out, refuse(code) }
	if e := validate("receipt", receipt); e != nil {
		return fail("invalid_shape")
	}
	raw, e := decode(text(receipt, "request_bytes"))
	if e != nil {
		return fail("invalid_encoding")
	}
	request, e := Parse(raw)
	if e != nil {
		return fail("invalid_encoding")
	}
	canonical, e := Canonical(request)
	if e != nil || !bytes.Equal(raw, canonical) {
		return fail("request_mismatch")
	}
	want, e := Canonical(expected)
	if e != nil || !bytes.Equal(raw, want) {
		return fail("request_mismatch")
	}
	if e = validate("request", request); e != nil {
		return fail("invalid_shape")
	}
	if text(request, "approver") != trust.Person || text(request, "organisation") != trust.Organisation {
		return fail("person_mismatch")
	}
	if number(request, "deadline") <= number(request, "not_before") {
		return fail("deadline_invalid")
	}
	signed := object(receipt, "binding")
	binding := object(signed, "binding")
	if text(binding, "person") != trust.Person || text(binding, "organisation") != trust.Organisation || text(binding, "identity_key") != trust.IdentityKey || text(binding, "certificate") != trust.Certificate {
		return fail("binding_mismatch")
	}
	issuerPublicKey := trust.IssuerPublicKey
	if text(binding, "issuer") != trust.Issuer {
		if trust.NamespaceIssuer == "" || text(binding, "issuer") != trust.NamespaceIssuer {
			return fail("binding_mismatch")
		}
		var err error
		issuerPublicKey, err = awid.ExtractPublicKey(trust.NamespaceIssuer)
		if err != nil {
			return fail("issuer_key_invalid")
		}
	}
	if !primePoint(issuerPublicKey) {
		return fail("issuer_key_invalid")
	}
	b, e := Canonical(binding)
	if e != nil {
		return fail("invalid_encoding")
	}
	sig, e := decode(text(signed, "signature"))
	if e != nil || !ed25519.Verify(issuerPublicKey, append(domain("binding"), b...), sig) {
		return fail("issuer_signature_invalid")
	}
	origin := text(binding, "origin")
	rp := text(binding, "rp_id")
	if checkSite(origin, rp) != nil {
		return fail("origin_invalid")
	}
	a := object(receipt, "assertion")
	selector, e := decode(text(a, "id"))
	if e != nil {
		return fail("invalid_encoding")
	}
	var selected map[string]any
	var selectedKey crypto.PublicKey
	seen := map[string]bool{}
	for _, entry := range binding["credentials"].([]any) {
		c := entry.(map[string]any)
		id, e := decode(text(c, "id"))
		if e != nil {
			return fail("invalid_encoding")
		}
		if seen[string(id)] {
			return fail("duplicate_credential")
		}
		seen[string(id)] = true
		if text(c, "grade") == "certified_hardware" && c["snapshot"] == nil {
			return fail("snapshot_invalid")
		}
		keyBytes, e := decode(text(c, "key"))
		if e != nil {
			return fail("invalid_encoding")
		}
		key, e := credentialKey(keyBytes, number(c, "algorithm"))
		if e != nil {
			return fail("credential_key_invalid")
		}
		if bytes.Equal(id, selector) {
			selected = c
			selectedKey = key
		}
	}
	if selected == nil {
		return fail("credential_not_enrolled")
	}
	client, e := decode(text(a, "client_data_json"))
	if e != nil {
		return fail("invalid_encoding")
	}
	data, e := parseClientData(client)
	if e != nil {
		return fail("assertion_invalid")
	}
	digest := sha256.Sum256(append(domain("request"), raw...))
	challenge, e := decode(data.Challenge)
	if e != nil || !bytes.Equal(challenge, digest[:]) || data.Type != "webauthn.get" || data.Origin != origin || data.CrossOrigin {
		return fail("assertion_invalid")
	}
	auth, e := decode(text(a, "authenticator_data"))
	if e != nil {
		return fail("invalid_encoding")
	}
	if len(auth) < 37 {
		return fail("assertion_invalid")
	}
	rpHash := sha256.Sum256([]byte(rp))
	flags := auth[32]
	if !bytes.Equal(auth[:32], rpHash[:]) || flags&5 != 5 || (flags&8 == 0 && flags&16 != 0) || flags&64 != 0 {
		return fail("assertion_invalid")
	}
	if flags&128 == 0 && len(auth) != 37 {
		return fail("assertion_invalid")
	}
	if flags&128 != 0 {
		var ext map[string]any
		if e = coseMode.Unmarshal(auth[37:], &ext); e != nil || ext == nil {
			return fail("assertion_invalid")
		}
	}
	if text(selected, "grade") == "certified_hardware" && flags&24 != 0 {
		return fail("credential_backup_eligible")
	}
	sig, e = decode(text(a, "signature"))
	if e != nil {
		return fail("invalid_encoding")
	}
	clientHash := sha256.Sum256(client)
	signedBytes := append(append([]byte{}, auth...), clientHash[:]...)
	hash := sha256.Sum256(signedBytes)
	valid := false
	switch key := selectedKey.(type) {
	case *ecdsa.PublicKey:
		valid = ecdsa.VerifyASN1(key, hash[:], sig)
	case ed25519.PublicKey:
		valid = ed25519.Verify(key, signedBytes, sig)
	case *rsa.PublicKey:
		valid = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], sig) == nil
	}
	if !valid {
		return fail("assertion_invalid")
	}
	out = CheckedApproval{Person: trust.Person, IdentityKey: trust.IdentityKey, Credential: text(selected, "id"), Grade: text(selected, "grade"), Digest: hex.EncodeToString(digest[:]), Origin: origin, Deadline: number(request, "deadline")}
	return request, out, nil
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func parseClientData(raw []byte) (clientData, error) {
	var out clientData
	// Duplicate/type checks apply without canonicalising these signed raw bytes.
	if len(raw) > 1<<20 || !utf8.Valid(raw) {
		return out, refuse("invalid_text")
	}
	if e := checkSurrogates(raw); e != nil {
		return out, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, err := readValue(d, 0)
	if err != nil {
		return out, err
	}
	// protocol.md:337-345 keeps the complete original client bytes signed.
	// Only whitespace may follow the one JSON object; do not reparse a struct.
	if _, err = d.Token(); err != io.EOF {
		return out, refuse("client_data_invalid")
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return out, refuse("client_data_invalid")
	}
	// protocol.md:337-345 requires verification of the original signed bytes.
	// Read only exact member names; JSON member names are case-sensitive.
	out.Type, ok = obj["type"].(string)
	if !ok {
		return out, refuse("client_data_invalid")
	}
	out.Origin, ok = obj["origin"].(string)
	if !ok {
		return out, refuse("client_data_invalid")
	}
	out.Challenge, ok = obj["challenge"].(string)
	if !ok {
		return out, refuse("client_data_invalid")
	}
	if value, exists := obj["crossOrigin"]; exists {
		out.CrossOrigin, ok = value.(bool)
		if !ok {
			return out, refuse("client_data_invalid")
		}
	}
	return out, nil
}
func VerifyHistorical(receipt, expected map[string]any, trust Trust) (CheckedApproval, error) {
	_, out, e := rawVerify(receipt, expected, trust)
	return out, e
}
func VerifyForEffect(receipt map[string]any, in EffectInputs) (CheckedApproval, error) {
	request, out, e := rawVerify(receipt, in.ExpectedRequest, in.Trust)
	if e != nil {
		return out, e
	}
	if text(request, "purpose") != "act_approval" {
		return out, refuse("purpose_invalid")
	}
	if in.Now < number(request, "not_before") || in.Now >= number(request, "deadline") {
		return out, refuse("request_expired")
	}
	if in.Trust.ObservedAt < 0 || in.Now < in.Trust.ObservedAt || in.Now-in.Trust.ObservedAt > 60 {
		return out, refuse("status_unavailable")
	}
	p, e := Canonical(in.Presenter)
	want, er := Canonical(object(request, "requester"))
	if e != nil || er != nil || !bytes.Equal(p, want) {
		return out, refuse("requester_mismatch")
	}
	grades := map[string]int{"passkey_uv": 0, "certified_hardware": 1}
	required, ok := grades[in.RequiredGrade]
	if !ok || grades[out.Grade] < required {
		return out, refuse("grade_insufficient")
	}
	if e = checkNonce(request, in.NonceKeys); e != nil {
		return out, e
	}
	return out, nil
}

func checkNonce(request map[string]any, keys map[string][]byte) error {
	nonce := object(request, "nonce")
	kid := text(nonce, "kid")
	secret := keys[kid]
	if len(secret) == 0 {
		return refuse("nonce_invalid")
	}
	core := map[string]any{}
	for k, v := range request {
		core[k] = v
	}
	core["nonce"] = map[string]any{"kid": kid, "value": ""}
	payload, e := Canonical(core)
	if e != nil {
		return e
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(domain("nonce"))
	mac.Write(payload)
	value, e := decode(text(nonce, "value"))
	if e != nil || !hmac.Equal(value, mac.Sum(nil)) {
		return refuse("nonce_invalid")
	}
	return nil
}
