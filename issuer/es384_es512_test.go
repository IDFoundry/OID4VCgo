package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func newECKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// acceptingES384ES512 has the SD-JWT VC configuration's proof types
// accept ES384 and ES512 besides ES256.
func acceptingES384ES512(cfg *issuer.Config, _ *issuer.Dependencies) {
	c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
	c.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
		oid4vci.ProofTypeJWT:         {ProofSigningAlgValuesSupported: []string{oid4vci.ES256, oid4vci.ES384, oid4vci.ES512}},
		oid4vci.ProofTypeAttestation: {ProofSigningAlgValuesSupported: []string{oid4vci.ES256, oid4vci.ES384, oid4vci.ES512}},
	}
	cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
}

func requestSDJWTWith(f credentialEndpointFixture, proofType, proof string) (oid4vci.CredentialResponse, error) {
	return f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{proofType: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
}

// A jwt proof (OID4VCI 1.0 Appendix F.1) signed ES384 by a P-384 jwk,
// or ES512 by a P-521 one, is accepted where the proof type lists the
// algorithm, and the credential is bound to that key; one whose alg
// isn't the one its key takes, or that the proof type doesn't list, is
// refused.
func TestRequestCredential_JWTProofES384ES512(t *testing.T) {
	for name, tc := range map[string]struct {
		alg     string
		curve   elliptic.Curve
		listed  bool
		wantErr string
	}{
		"ES384 by P-384":           {"ES384", elliptic.P384(), true, ""},
		"ES512 by P-521":           {"ES512", elliptic.P521(), true, ""},
		"ES512 by P-384":           {"ES512", elliptic.P384(), true, "ES512 requires a P-521 public key"},
		"ES256 by P-521":           {"ES256", elliptic.P521(), true, "ES256 requires a P-256 public key"},
		"ES384 by P-384, unlisted": {"ES384", elliptic.P384(), false, `alg "ES384" is not supported`},
	} {
		t.Run(name, func(t *testing.T) {
			var f credentialEndpointFixture
			if tc.listed {
				f = newCredentialEndpointFixture(t, acceptingES384ES512)
			} else {
				f = newCredentialEndpointFixture(t)
			}
			key := newECKey(t, tc.curve)
			var jwkObj map[string]any
			if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
				t.Fatal(err)
			}
			proof := testjose.SignClaims(t, tc.alg, key, map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj},
				map[string]any{"aud": testIssuer, "iat": time.Now().Unix(), "nonce": f.issueNonce(t)})
			resp, err := requestSDJWTWith(f, oid4vci.ProofTypeJWT, proof)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(errorChain(err), tc.wantErr) {
					t.Fatalf("RequestCredential = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
			assertBoundTo(t, f, resp, key)
		})
	}
}

// A key attestation (OID4VCI 1.0 Appendix D.1) signed ES384 by a
// P-384 attester certificate, or ES512 by a P-521 one, is accepted by
// X5CAttestationVerifier, attesting a P-384 key; signed under an alg
// its certificate's key doesn't take, it's refused.
func TestRequestCredential_AttestationProofES384ES512(t *testing.T) {
	ca, caKey := testcert.CA(t, "attester CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for name, tc := range map[string]struct {
		alg     string
		curve   elliptic.Curve
		wantErr string
	}{
		"ES384 by P-384": {"ES384", elliptic.P384(), ""},
		"ES512 by P-521": {"ES512", elliptic.P521(), ""},
		"ES384 by P-521": {"ES384", elliptic.P521(), `header alg "ES384" does not match expected "ES512"`},
		"ES256 by P-384": {"ES256", elliptic.P384(), `header alg "ES256" does not match expected "ES384"`},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, acceptingES384ES512, func(_ *issuer.Config, deps *issuer.Dependencies) {
				deps.AttestationVerifier = issuer.X5CAttestationVerifier{Roots: roots}
			})
			attester := newECKey(t, tc.curve)
			leaf := testcert.LeafFor(t, "attester "+name, &attester.PublicKey, ca, caKey)
			holder := newECKey(t, elliptic.P384())
			att := testjose.SignClaims(t, tc.alg, attester, map[string]any{
				"typ": attestation.TypHeader, "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
			}, map[string]any{
				"iat": time.Now().Unix(), "nonce": f.issueNonce(t), "attested_keys": []json.RawMessage{jwkJSON(t, &holder.PublicKey)},
			})
			resp, err := requestSDJWTWith(f, oid4vci.ProofTypeAttestation, att)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(errorChain(err), tc.wantErr) {
					t.Fatalf("RequestCredential = %v, want an error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
			assertBoundTo(t, f, resp, holder)
		})
	}
}

// proof_signing_alg_values_supported may list ES384 and ES512, which
// the issuer verifies (OID4VCI 1.0 §12.2.4), but not an algorithm it
// can't.
func TestNew_ProofSigningAlgValuesES384ES512(t *testing.T) {
	if _, err := tryCredentialEndpointFixture(t, acceptingES384ES512); err != nil {
		t.Errorf("New refused ES384 and ES512: %v", err)
	}
	_, err := tryCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		c.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{oid4vci.ES256, "PS256"}},
		}
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
	})
	if err == nil || !strings.Contains(err.Error(), `"PS256", which this issuer can't verify`) {
		t.Errorf("New = %v, want PS256 refused", err)
	}
}

// assertBoundTo checks resp's one credential verifies under f's signer
// and names key in cnf.
func assertBoundTo(t *testing.T, f credentialEndpointFixture, resp oid4vci.CredentialResponse, key *ecdsa.PrivateKey) {
	t.Helper()
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
	}
	payload, _, err := sdjwtvc.Verify(resp.Credentials[0].Credential, &f.sdjwtSigner.Signer.(*ecdsa.PrivateKey).PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingNotRequired,
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	cnf, _ := payload["cnf"].(map[string]any)
	got, err := json.Marshal(cnf["jwk"])
	if err != nil {
		t.Fatal(err)
	}
	var gotJWK, wantJWK map[string]any
	if json.Unmarshal(got, &gotJWK) != nil || json.Unmarshal(jwkJSON(t, &key.PublicKey), &wantJWK) != nil ||
		gotJWK["crv"] != wantJWK["crv"] || gotJWK["x"] != wantJWK["x"] || gotJWK["y"] != wantJWK["y"] {
		t.Errorf("cnf.jwk = %s, want %s", got, jwkJSON(t, &key.PublicKey))
	}
}

// errorChain is err's message and its causes', for errors whose
// message is only the code a Wallet sees.
func errorChain(err error) string {
	var b strings.Builder
	for e := err; e != nil; {
		b.WriteString(e.Error())
		b.WriteString(" | ")
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			break
		}
		e = u.Unwrap()
	}
	return b.String()
}

// The x5c resolvers take the algorithm from the certificate's key:
// ES384 for P-384, ES512 for P-521.
func TestX5CResolvers_ES384ES512(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for want, c := range map[jose.Alg]elliptic.Curve{jose.ES384: elliptic.P384(), jose.ES512: elliptic.P521()} {
		key := newECKey(t, c)
		leaf := testcert.LeafFor(t, "leaf "+string(want), &key.PublicKey, ca, caKey)
		pub, alg, err := issuer.X5CProofBindingKeyResolver{Roots: roots}.ResolveProofBindingKey(context.Background(), x5cProofHeader(leaf))
		if err != nil || alg != want || !key.PublicKey.Equal(pub) {
			t.Errorf("ResolveProofBindingKey = %q, %v, want %q and the leaf's key", alg, err, want)
		}
		att := testjose.Sign(t, string(want), key, map[string]any{
			"typ": attestation.TypHeader, "x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
		}, []byte(`{"iat":1,"attested_keys":[{"kty":"EC"}]}`))
		parsed, err := attestation.Parse(att)
		if err != nil {
			t.Fatal(err)
		}
		pub, alg, err = issuer.X5CAttestationVerifier{Roots: roots}.ResolveAttestationKey(context.Background(), parsed)
		if err != nil || alg != want || !key.PublicKey.Equal(pub) {
			t.Errorf("ResolveAttestationKey = %q, %v, want %q and the leaf's key", alg, err, want)
		}
	}
}

// A P-384 or P-521 key, which a jwk now parses as, is still no
// response-encryption key: ECDH-ES here is on P-256 only.
func TestEncryptResponseBody_RefusesNonP256Key(t *testing.T) {
	iss, _ := newEncryptionIssuer(t, nil)
	for _, c := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		_, _, err := iss.EncryptResponseBody([]byte(`{}`), &issuer.ResponseEncryptionRequest{Enc: jwe.A128GCM, JWK: encryptionJWK(t, &newECKey(t, c).PublicKey)})
		assertIssuerError(t, err, issuer.ErrorInvalidEncryptionParameters)
	}
}
