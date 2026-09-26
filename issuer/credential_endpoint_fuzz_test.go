package issuer_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// fuzzNonceCounter keeps each fuzz iteration's nonce unique, since
// RequestCredential consumes the nonce it's given.
var fuzzNonceCounter atomic.Uint64

// issueFuzzNonce issues a fresh nonce into f's store and returns it.
func issueFuzzNonce(t *testing.T, f credentialEndpointFixture) string {
	nonce := "fuzz-nonce-" + strconv.FormatUint(fuzzNonceCounter.Add(1), 10)
	if err := f.nonces.Issue(context.Background(), issuer.NonceIssuance{
		Nonce: nonce, ExpiresAt: f.now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue nonce: %v", err)
	}
	return nonce
}

// withFuzzNonce replaces payload's "nonce" claim with nonce if payload
// is a JSON object that has one, so a mutated payload keeps passing
// the nonce check unless the fuzzer removes or retypes the claim
// itself. Anything else is returned unchanged.
func withFuzzNonce(payload []byte, nonce string) []byte {
	var m map[string]any
	if json.Unmarshal(payload, &m) != nil || m == nil {
		return payload
	}
	if _, ok := m["nonce"]; !ok {
		return payload
	}
	m["nonce"] = nonce
	out, err := json.Marshal(m)
	if err != nil {
		return payload
	}
	return out
}

// FuzzRequestCredentialSignedProof exercises RequestCredential's
// jwt-type proof handling (Appendix F.1) past the signature check: the
// proof's header (jwk/kid/x5c selection, typ, alg) and its claims (aud,
// iat, nonce), then credential issuance. A Wallet signs its own proofs
// with its own key, so any attacker can produce a validly signed proof
// carrying arbitrary content — the harness does the same, signing the
// fuzzed header and payload with walletKey. With bindJWK set, the
// harness overwrites the header's "jwk" member with walletKey's own
// public key, so header mutations still verify; otherwise kid/x5c
// headers resolve to walletKey through ProofBindingKeys.
func FuzzRequestCredentialSignedProof(f *testing.F) {
	walletKey := testP256Key(f)
	fx := newCredentialEndpointFixture(f, func(_ *issuer.Config, d *issuer.Dependencies) {
		d.ProofBindingKeys = fixedProofBindingKeyResolver{pub: &walletKey.PublicKey}
	})
	var walletJWK map[string]any
	if err := json.Unmarshal(jwkJSON(f, &walletKey.PublicKey), &walletJWK); err != nil {
		f.Fatalf("json.Unmarshal: %v", err)
	}

	payload := []byte(`{"aud":"` + testIssuer + `","iat":` + strconv.FormatInt(fx.now.Unix(), 10) + `,"nonce":"n"}`)
	f.Add([]byte(`{"typ":"openid4vci-proof+jwt","jwk":{}}`), payload, true)
	f.Add([]byte(`{"typ":"openid4vci-proof+jwt","kid":"did:example:wallet#1"}`), payload, false)
	f.Add([]byte(`{"typ":"openid4vci-proof+jwt","x5c":["AAAA"]}`), payload, false)
	f.Add([]byte(`{"typ":"openid4vci-proof+jwt","jwk":{},"kid":"k"}`), payload, true)

	f.Fuzz(func(t *testing.T, header, payload []byte, bindJWK bool) {
		var h map[string]any
		if err := json.Unmarshal(header, &h); err != nil || h == nil {
			return
		}
		if bindJWK {
			h["jwk"] = walletJWK
		}
		proof, err := jose.Sign(jose.ES256, walletKey, h, withFuzzNonce(payload, issueFuzzNonce(t, fx)))
		if err != nil {
			return
		}
		resp, err := requestSDJWTWithProof(fx, oid4vci.ProofTypeJWT, proof)
		if err != nil {
			return
		}
		if len(resp.Credentials) != 1 {
			t.Fatalf("got %d credentials for one proof, want 1", len(resp.Credentials))
		}
	})
}

// FuzzRequestCredentialSignedAttestation exercises RequestCredential's
// attestation-type proof handling (Appendix D/F.3) past the signature
// check: the Key Attestation's claims — attested_keys parsing and the
// batch_size fan-out cap, iat/exp, nonce — then per-key credential
// issuance. The harness signs the fuzzed claims with the attestation
// provider's key the fixture trusts, modelling a trusted provider
// whose output is malformed or whose key is compromised.
func FuzzRequestCredentialSignedAttestation(f *testing.F) {
	fx := newCredentialEndpointFixture(f)
	rawJWK := jwkJSON(f, &testP256Key(f).PublicKey)
	seed, err := attestation.Issue(fx.attestationSigner, jose.ES256, attestation.Header{}, attestation.Claims{
		IssuedAt: fx.now.Unix(), AttestedKeys: []json.RawMessage{rawJWK, rawJWK}, Nonce: "n",
	})
	if err != nil {
		f.Fatalf("attestation.Issue: %v", err)
	}
	header, payload, err := jose.DecodeUnverified(seed)
	if err != nil {
		f.Fatalf("DecodeUnverified: %v", err)
	}
	f.Add(payload)
	f.Add([]byte(`{"iat":` + strconv.FormatInt(fx.now.Unix(), 10) + `,"attested_keys":[],"nonce":"n"}`))

	f.Fuzz(func(t *testing.T, payload []byte) {
		proof, err := jose.Sign(jose.ES256, fx.attestationSigner, header, withFuzzNonce(payload, issueFuzzNonce(t, fx)))
		if err != nil {
			return
		}
		resp, err := requestSDJWTWithProof(fx, oid4vci.ProofTypeAttestation, proof)
		if err != nil {
			return
		}
		if n := len(resp.Credentials); n == 0 || n > 2 {
			t.Fatalf("got %d credentials, want 1..BatchSize (2)", n)
		}
	})
}

// FuzzResolveProofBindingKey exercises
// X5CProofBindingKeyResolver.ResolveProofBindingKey against arbitrary
// JSON headers — the issuer-side counterpart of verifier's
// FuzzResolveIssuerKey. Unlike that target, Roots holds a real CA and
// the seed carries a chain that validates against it, so mutations
// that keep the chain intact also reach the leaf's key/alg handling.
func FuzzResolveProofBindingKey(f *testing.F) {
	ca, caKey := testcert.CA(f, "fuzz root")
	leaf, _ := testcert.Leaf(f, "fuzz leaf", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := issuer.X5CProofBindingKeyResolver{Roots: roots}

	leafB64 := base64.StdEncoding.EncodeToString(leaf.Raw)
	caB64 := base64.StdEncoding.EncodeToString(ca.Raw)
	f.Add([]byte(`{"x5c":["` + leafB64 + `"]}`))
	f.Add([]byte(`{"x5c":["` + leafB64 + `","` + caB64 + `"]}`))
	f.Add([]byte(`{"x5c":["` + caB64 + `"]}`))
	f.Add([]byte(`{"x5c":[]}`))
	f.Add([]byte(`{"x5c":"not-an-array"}`))
	f.Add([]byte(`{"x5c":[1,2,3]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var header map[string]any
		if err := json.Unmarshal(data, &header); err != nil {
			return
		}
		pub, alg, err := resolver.ResolveProofBindingKey(context.Background(), header)
		if err != nil {
			return
		}
		if pub == nil || alg == "" {
			t.Fatalf("ResolveProofBindingKey succeeded with pub=%v alg=%q", pub, alg)
		}
	})
}
