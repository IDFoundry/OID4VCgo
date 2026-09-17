package attestation

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// TestParse_OID4VCIAppendixDExample reproduces Appendix D.1's own
// worked example claims set (the header/payload shown there isn't
// independently signature-verifiable — no real key is given — so this
// checks claims parsing matches the spec's own field values exactly,
// the same limitation clientattestation_test.go documents for FAPIgo's
// sibling draft-07 example).
func TestParse_OID4VCIAppendixDExample(t *testing.T) {
	const examplePayload = `{
		"iss": "<identifier of the issuer of this key attestation>",
		"iat": 1516247022,
		"exp": 1541493724,
		"key_storage": [ "iso_18045_moderate" ],
		"user_authentication": [ "iso_18045_moderate" ],
		"attested_keys": [
			{
				"kty": "EC",
				"crv": "P-256",
				"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
				"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
			}
		]
	}`
	key := testKey(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": TypHeader}, []byte(examplePayload))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := parsed.Verify(&key.PublicKey, jose.ES256, VerifyOptions{Now: time.Unix(1520000000, 0)})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Issuer != "<identifier of the issuer of this key attestation>" {
		t.Errorf("Issuer = %q", verified.Issuer)
	}
	if verified.IssuedAt.Unix() != 1516247022 {
		t.Errorf("IssuedAt = %v", verified.IssuedAt)
	}
	if verified.ExpiresAt == nil || verified.ExpiresAt.Unix() != 1541493724 {
		t.Errorf("ExpiresAt = %v", verified.ExpiresAt)
	}
	if len(verified.KeyStorage) != 1 || verified.KeyStorage[0] != ISO18045Moderate {
		t.Errorf("KeyStorage = %v", verified.KeyStorage)
	}
	if len(verified.UserAuthentication) != 1 || verified.UserAuthentication[0] != ISO18045Moderate {
		t.Errorf("UserAuthentication = %v", verified.UserAuthentication)
	}
	if len(verified.AttestedKeys) != 1 {
		t.Fatalf("got %d attested keys, want 1", len(verified.AttestedKeys))
	}

	// The example's own attested key: reconstruct it (SEC1 uncompressed
	// point: 0x04 || X || Y) and confirm KeyAttested matches — avoids
	// the deprecated PublicKey.X/Y field access (see crypto/ecdsa's own
	// doc comment as of Go 1.26).
	xBytes, err := b64.DecodeString("TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc")
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}
	yBytes, err := b64.DecodeString("ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ")
	if err != nil {
		t.Fatalf("decode y: %v", err)
	}
	uncompressed := append([]byte{0x04}, append(xBytes, yBytes...)...)
	exampleKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), uncompressed)
	if err != nil {
		t.Fatalf("ParseUncompressedPublicKey: %v", err)
	}

	ok, err := verified.KeyAttested(exampleKey)
	if err != nil {
		t.Fatalf("KeyAttested: %v", err)
	}
	if !ok {
		t.Errorf("KeyAttested(example key) = false, want true")
	}

	other := testKey(t)
	ok, err = verified.KeyAttested(&other.PublicKey)
	if err != nil {
		t.Fatalf("KeyAttested: %v", err)
	}
	if ok {
		t.Errorf("KeyAttested(unrelated key) = true, want false")
	}
}

func TestIssueVerify_RoundTrip(t *testing.T) {
	issuerKey := testKey(t)
	attestedKey := testKey(t)
	attestedJWK, err := marshalJWK(&attestedKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalJWK: %v", err)
	}

	now := time.Now()
	iat := now.Unix()
	exp := now.Add(time.Hour).Unix()
	compact, err := Issue(issuerKey, jose.ES256, Header{KeyID: "issuer-key-1"}, Claims{
		Issuer:       "https://wallet-provider.example.com",
		IssuedAt:     iat,
		ExpiresAt:    &exp,
		AttestedKeys: []json.RawMessage{attestedJWK},
		KeyStorage:   []AttackPotentialResistance{ISO18045High},
		Nonce:        "the-nonce",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.KeyID() != "issuer-key-1" {
		t.Errorf("KeyID() = %q, want issuer-key-1", parsed.KeyID())
	}

	verified, err := parsed.Verify(&issuerKey.PublicKey, jose.ES256, VerifyOptions{
		Now: now, ExpectedNonce: "the-nonce",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	ok, err := verified.KeyAttested(&attestedKey.PublicKey)
	if err != nil {
		t.Fatalf("KeyAttested: %v", err)
	}
	if !ok {
		t.Errorf("KeyAttested = false, want true")
	}
}

func TestIssueVerify_Ed25519AttestedKey(t *testing.T) {
	issuerKey := testKey(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	attestedJWK, err := marshalJWK(pub)
	if err != nil {
		t.Fatalf("marshalJWK: %v", err)
	}

	now := time.Now()
	compact, err := Issue(issuerKey, jose.ES256, Header{}, Claims{
		IssuedAt:     now.Unix(),
		AttestedKeys: []json.RawMessage{attestedJWK},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := parsed.Verify(&issuerKey.PublicKey, jose.ES256, VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	ok, err := verified.KeyAttested(pub)
	if err != nil {
		t.Fatalf("KeyAttested: %v", err)
	}
	if !ok {
		t.Errorf("KeyAttested(ed25519 key) = false, want true")
	}
}

func TestIssue_RequiresIssuedAt(t *testing.T) {
	key := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	_, err := Issue(key, jose.ES256, Header{}, Claims{AttestedKeys: []json.RawMessage{attestedJWK}})
	if err == nil {
		t.Errorf("Issue accepted Claims with no IssuedAt")
	}
}

func TestIssue_RequiresAttestedKeys(t *testing.T) {
	key := testKey(t)
	_, err := Issue(key, jose.ES256, Header{}, Claims{IssuedAt: time.Now().Unix()})
	if err == nil {
		t.Errorf("Issue accepted Claims with no AttestedKeys")
	}
}

func TestParse_RejectsMissingAttestedKeys(t *testing.T) {
	key := testKey(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": TypHeader}, []byte(`{"iat":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Parse(compact); err == nil {
		t.Errorf("Parse accepted claims with no attested_keys")
	}
}

func TestVerify_RejectsExpired(t *testing.T) {
	issuerKey := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	now := time.Now()
	exp := now.Add(-time.Minute).Unix()
	compact, err := Issue(issuerKey, jose.ES256, Header{}, Claims{
		IssuedAt: now.Unix(), ExpiresAt: &exp, AttestedKeys: []json.RawMessage{attestedJWK},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&issuerKey.PublicKey, jose.ES256, VerifyOptions{Now: now}); err == nil {
		t.Errorf("Verify accepted an expired attestation")
	}
}

func TestVerify_RequireExpiry(t *testing.T) {
	issuerKey := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	now := time.Now()
	compact, err := Issue(issuerKey, jose.ES256, Header{}, Claims{
		IssuedAt: now.Unix(), AttestedKeys: []json.RawMessage{attestedJWK},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&issuerKey.PublicKey, jose.ES256, VerifyOptions{Now: now, RequireExpiry: true}); err == nil {
		t.Errorf("Verify accepted a missing exp when RequireExpiry was set")
	}
}

func TestVerify_RejectsWrongNonce(t *testing.T) {
	issuerKey := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	now := time.Now()
	compact, err := Issue(issuerKey, jose.ES256, Header{}, Claims{
		IssuedAt: now.Unix(), AttestedKeys: []json.RawMessage{attestedJWK}, Nonce: "correct",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&issuerKey.PublicKey, jose.ES256, VerifyOptions{Now: now, ExpectedNonce: "wrong"}); err == nil {
		t.Errorf("Verify accepted the wrong nonce")
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	issuerKey := testKey(t)
	otherKey := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	now := time.Now()
	compact, err := Issue(issuerKey, jose.ES256, Header{}, Claims{
		IssuedAt: now.Unix(), AttestedKeys: []json.RawMessage{attestedJWK},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&otherKey.PublicKey, jose.ES256, VerifyOptions{Now: now}); err == nil {
		t.Errorf("Verify accepted a signature under the wrong key")
	}
}

func TestIssue_RejectsUnmarshalableStatus(t *testing.T) {
	key := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	_, err := Issue(key, jose.ES256, Header{}, Claims{
		IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{attestedJWK},
		Status: map[string]any{"bad": make(chan int)},
	})
	if err == nil {
		t.Errorf("Issue accepted an unmarshalable Status value")
	}
}

func TestIssue_PropagatesSignError(t *testing.T) {
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	// EdDSA with a P-256 signer: internal/jose.Sign rejects the
	// algorithm/key mismatch.
	_, err := Issue(testKey(t), jose.EdDSA, Header{}, Claims{
		IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{attestedJWK},
	})
	if err == nil {
		t.Errorf("Issue accepted a signer that doesn't match the requested algorithm")
	}
}

func TestParse_RejectsMalformedCompact(t *testing.T) {
	if _, err := Parse("not-a-jwt"); err == nil {
		t.Errorf("Parse accepted a malformed compact JWS")
	}
}

func TestParse_RejectsNonJSONPayload(t *testing.T) {
	key := testKey(t)
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": TypHeader}, []byte("not json"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Parse(compact); err == nil {
		t.Errorf("Parse accepted a non-JSON payload")
	}
}

func TestParse_RejectsMissingIssuedAt(t *testing.T) {
	key := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	raw, err := json.Marshal(map[string]any{"attested_keys": []json.RawMessage{attestedJWK}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": TypHeader}, raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Parse(compact); err == nil {
		t.Errorf("Parse accepted claims with no iat")
	}
}

func TestIssueVerify_NoOptionalHeaders(t *testing.T) {
	issuerKey := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	compact, err := Issue(issuerKey, jose.ES256, Header{}, Claims{
		IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{attestedJWK},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.X5C() != nil {
		t.Errorf("X5C() = %v, want nil", parsed.X5C())
	}
	if parsed.TrustChain() != nil {
		t.Errorf("TrustChain() = %v, want nil", parsed.TrustChain())
	}
}

func TestKeyAttested_IgnoresUnparseableAttestedKey(t *testing.T) {
	attestedKey := testKey(t)
	goodJWK, err := marshalJWK(&attestedKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalJWK: %v", err)
	}
	v := VerifiedClaims{AttestedKeys: []json.RawMessage{[]byte("not json"), goodJWK}}
	ok, err := v.KeyAttested(&attestedKey.PublicKey)
	if err != nil {
		t.Fatalf("KeyAttested: %v", err)
	}
	if !ok {
		t.Errorf("KeyAttested = false, want true (should skip the unparseable entry and still match the good one)")
	}
}

func TestVerify_RejectsTypMismatch(t *testing.T) {
	key := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	raw, err := json.Marshal(map[string]any{"iat": time.Now().Unix(), "attested_keys": []json.RawMessage{attestedJWK}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "not-the-right-typ"}, raw)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&key.PublicKey, jose.ES256, VerifyOptions{Now: time.Now()}); err == nil {
		t.Errorf("Verify accepted the wrong typ header")
	}
}

func TestVerify_RequiresNowWhenExpiryPresent(t *testing.T) {
	issuerKey := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	exp := time.Now().Add(time.Hour).Unix()
	compact, err := Issue(issuerKey, jose.ES256, Header{}, Claims{
		IssuedAt: time.Now().Unix(), ExpiresAt: &exp, AttestedKeys: []json.RawMessage{attestedJWK},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parsed.Verify(&issuerKey.PublicKey, jose.ES256, VerifyOptions{}); err == nil {
		t.Errorf("Verify accepted a zero Now when the attestation has an exp claim")
	}
}

func TestHeader_X5CAndTrustChain(t *testing.T) {
	issuerKey := testKey(t)
	attestedJWK, _ := marshalJWK(&testKey(t).PublicKey)
	compact, err := Issue(issuerKey, jose.ES256, Header{
		X5C:        []string{"MIIDQjCCA..."},
		TrustChain: []string{"chain-element-1", "chain-element-2"},
	}, Claims{IssuedAt: time.Now().Unix(), AttestedKeys: []json.RawMessage{attestedJWK}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(parsed.X5C()) != 1 || parsed.X5C()[0] != "MIIDQjCCA..." {
		t.Errorf("X5C() = %v", parsed.X5C())
	}
	if len(parsed.TrustChain()) != 2 {
		t.Errorf("TrustChain() = %v", parsed.TrustChain())
	}
}
