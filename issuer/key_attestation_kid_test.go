package issuer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// jwtProofByKid is a jwt proof by key naming its key by kid beside
// keyAttestation (Appendix F.1's second example).
func jwtProofByKid(t *testing.T, key *ecdsa.PrivateKey, kid, nonce, keyAttestation string) string {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"aud": testIssuer, "iat": time.Now().Unix(), "nonce": nonce})
	raw, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "openid4vci-proof+jwt", "kid": kid, "key_attestation": keyAttestation}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// keyAttestationWithKids is a key attestation for the jwt proof type,
// by signer, issued at issuedAt, attesting keys, each JWK with the kid
// at its index in kids ("" for none).
func keyAttestationWithKids(t *testing.T, signer *ecdsa.PrivateKey, nonce string, issuedAt time.Time, keys []crypto.PublicKey, kids []string) string {
	t.Helper()
	raws := make([]json.RawMessage, len(keys))
	for i, pub := range keys {
		var obj map[string]any
		if err := json.Unmarshal(jwkJSON(t, pub), &obj); err != nil {
			t.Fatal(err)
		}
		if kids[i] != "" {
			obj["kid"] = kids[i]
		}
		raws[i], _ = json.Marshal(obj)
	}
	exp := time.Now().Add(time.Hour).Unix()
	compact, err := attestation.Issue(signer, jose.ES256, attestation.Header{}, attestation.Claims{IssuedAt: issuedAt.Unix(), ExpiresAt: &exp, AttestedKeys: raws, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// requestSDJWT requests f's SD-JWT VC configuration with proofs.
func requestSDJWT(f credentialEndpointFixture, proofs ...string) (oid4vci.CredentialResponse, error) {
	return f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: proofs},
		SDJWTClaims:               testSDJWTClaims(),
	})
}

// A jwt proof may name its key by kid beside its key_attestation: the
// key is the attested one with that kid, or, where none has a kid, the
// attested one the proof verifies under (Appendix F.1).
func TestRequestCredential_JWTProofKidNamesAttestedKey(t *testing.T) {
	a, b := testP256Key(t), testP256Key(t)
	keys := []crypto.PublicKey{&b.PublicKey, &a.PublicKey}
	for name, tc := range map[string]struct {
		kids    []string
		kid     string
		wantErr bool
	}{
		"by its kid":                  {kids: []string{"1", "0"}, kid: "0"},
		"attested keys without a kid": {kids: []string{"", ""}, kid: "0"},
		"a kid naming another key":    {kids: []string{"1", "0"}, kid: "1", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t)
			n := f.issueNonce(t)
			ka := keyAttestationWithKids(t, f.attestationSigner, n, time.Now(), keys, tc.kids)
			resp, err := requestSDJWT(f, jwtProofByKid(t, a, tc.kid, n, ka))
			if tc.wantErr {
				assertIssuerError(t, err, issuer.ErrorInvalidProof)
				return
			}
			if err != nil || len(resp.Credentials) != 2 {
				t.Fatalf("issued %d credentials, %v; want one for each attested key", len(resp.Credentials), err)
			}
		})
	}
}

// An issuer verifying no key attestations takes a jwt proof carrying
// the OPTIONAL key_attestation header as one without it, binding the
// proof's own key.
func TestRequestCredential_KeyAttestationHeaderIgnoredWithoutVerifier(t *testing.T) {
	a := testP256Key(t)
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		delete(cfg.CredentialConfigurationsSupported[testSDJWTConfigID].ProofTypesSupported, oid4vci.ProofTypeAttestation)
		deps.AttestationVerifier = nil
	})
	n := f.issueNonce(t)
	ka := keyAttestationForJWT(t, testP256Key(t), n, false, &a.PublicKey)
	resp, err := requestSDJWT(f, jwtProofWithKeyAttestation(t, a, n, ka))
	if err != nil || len(resp.Credentials) != 1 {
		t.Fatalf("issued %d credentials, %v; want one, bound to the proof's key", len(resp.Credentials), err)
	}
}

// Without a Nonce Endpoint, a jwt proof dates itself (MaxProofAge): the
// key attestation it carries may be one issued earlier, as HAIP 1.0
// §9.2 has Wallet Providers do.
func TestRequestCredential_EarlierKeyAttestationWithoutNonceEndpoint(t *testing.T) {
	a := testP256Key(t)
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		cfg.Endpoints.Nonce = fapi.URL{}
		cfg.Limits.MaxProofAge = 5 * time.Minute
	})
	ka := keyAttestationWithKids(t, f.attestationSigner, "", time.Now().Add(-24*time.Hour), []crypto.PublicKey{&a.PublicKey}, []string{""})
	resp, err := requestSDJWT(f, jwtProofWithKeyAttestation(t, a, "", ka))
	if err != nil || len(resp.Credentials) != 1 {
		t.Fatalf("issued %d credentials, %v; want one", len(resp.Credentials), err)
	}
}
