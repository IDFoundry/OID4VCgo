package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// proofWith is a jwt-type proof by key for nonce, with its header and
// body changed by the given functions, signed by signer (key when nil).
func proofWith(t *testing.T, key, signer *ecdsa.PrivateKey, nonce string, header, body func(map[string]any)) string {
	t.Helper()
	var jwkObj map[string]any
	if err := json.Unmarshal(jwkJSON(t, &key.PublicKey), &jwkObj); err != nil {
		t.Fatal(err)
	}
	h := map[string]any{"typ": "openid4vci-proof+jwt", "jwk": jwkObj}
	b := map[string]any{"aud": testIssuer, "iat": time.Now().Unix(), "nonce": nonce}
	if header != nil {
		header(h)
	}
	if body != nil {
		body(b)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if signer == nil {
		signer = key
	}
	compact, err := jose.Sign(jose.ES256, signer, h, raw)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// proofVector is a credential request with one thing wrong in its
// proofs, which RequestCredential must refuse with code.
type proofVector struct {
	id, clause string
	code       issuer.ErrorCode
	// proofs builds the request's proofs, for nonce, a fresh c_nonce.
	proofs func(t *testing.T, f credentialEndpointFixture, nonce string) map[string][]string
	// client, when set, is the authenticated client instead of
	// "test-client".
	client string
	// noNonceEndpoint runs the vector against an issuer without a Nonce
	// Endpoint, whose proofs iat dates (Appendix F.4).
	noNonceEndpoint bool
}

// withoutNonceEndpoint has the issuer publish no Nonce Endpoint: a
// proof's iat, within a minute, is then what dates it.
func withoutNonceEndpoint(cfg *issuer.Config, _ *issuer.Dependencies) {
	cfg.Endpoints.Nonce = issuer.Endpoints{}.Nonce
	cfg.Limits.MaxProofAge = time.Minute
}

func jwtProofs(p ...string) map[string][]string { return map[string][]string{oid4vci.ProofTypeJWT: p} }

var proofNegativeVectors = []proofVector{
	{id: "proof-typ-wrong", clause: "OpenID4VCI 1.0 Appendix F.1 (typ)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, func(h map[string]any) { h["typ"] = "JWT" }, nil))
		}},
	{id: "proof-typ-missing", clause: "Appendix F.1 (typ)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, func(h map[string]any) { delete(h, "typ") }, nil))
		}},
	{id: "proof-alg-none", clause: "Appendix F.1 (alg MUST NOT be none)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			parts := strings.Split(proofWith(t, newP256(t), nil, n, nil, nil), ".")
			var h map[string]any
			raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
			_ = json.Unmarshal(raw, &h)
			h["alg"] = "none"
			hb, _ := json.Marshal(h)
			return jwtProofs(base64.RawURLEncoding.EncodeToString(hb) + "." + parts[1] + ".")
		}},
	{id: "proof-signed-by-another-key", clause: "Appendix F.4 (signature by the jwk)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), newP256(t), n, nil, nil))
		}},
	{id: "proof-payload-tampered", clause: "RFC 7515 §5.2 (signature)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			parts := strings.Split(proofWith(t, newP256(t), nil, n, nil, nil), ".")
			body, _ := json.Marshal(map[string]any{"aud": testIssuer, "iat": time.Now().Unix(), "nonce": n, "x": 1})
			return jwtProofs(parts[0] + "." + base64.RawURLEncoding.EncodeToString(body) + "." + parts[2])
		}},
	{id: "proof-no-key", clause: "Appendix F.1 (one of kid, jwk, x5c)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, func(h map[string]any) { delete(h, "jwk") }, nil))
		}},
	{id: "proof-jwk-and-kid", clause: "Appendix F.1 (exactly one of kid, jwk, x5c)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, func(h map[string]any) { h["kid"] = "k1" }, nil))
		}},
	{id: "proof-jwk-holds-the-private-key", clause: "Appendix F.1 (jwk MUST NOT contain a private key)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			key := newP256(t)
			return jwtProofs(proofWith(t, key, nil, n, func(h map[string]any) {
				d, err := key.Bytes()
				if err != nil {
					t.Fatal(err)
				}
				h["jwk"].(map[string]any)["d"] = base64.RawURLEncoding.EncodeToString(d)
			}, nil))
		}},
	{id: "proof-aud-another-issuer", clause: "Appendix F.1 (aud)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { b["aud"] = "https://another.example.com" }))
		}},
	{id: "proof-aud-missing", clause: "Appendix F.1 (aud REQUIRED)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { delete(b, "aud") }))
		}},
	{id: "proof-iat-missing", clause: "Appendix F.1 (iat REQUIRED)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { delete(b, "iat") }))
		}},
	{id: "proof-iat-in-the-future", clause: "Appendix F.4 (iat within a window, without a Nonce Endpoint)", code: issuer.ErrorInvalidProof, noNonceEndpoint: true,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { b["iat"] = time.Now().Add(time.Hour).Unix() }))
		}},
	{id: "proof-iat-too-old", clause: "Appendix F.4 (iat within a window, without a Nonce Endpoint)", code: issuer.ErrorInvalidProof, noNonceEndpoint: true,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { b["iat"] = time.Now().Add(-time.Hour).Unix() }))
		}},
	{id: "proof-iat-a-string", clause: "RFC 7519 §2 (NumericDate)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { b["iat"] = "1767225600" }))
		}},
	{id: "proof-nonce-missing", clause: "OpenID4VCI 1.0 §7 (c_nonce, with a Nonce Endpoint)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { delete(b, "nonce") }))
		}},
	{id: "proof-nonce-unknown", clause: "§8.3.1.2 (invalid_nonce)", code: issuer.ErrorInvalidNonce,
		proofs: func(t *testing.T, _ credentialEndpointFixture, _ string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, "not-a-c-nonce", nil, nil))
		}},
	{id: "proof-nonce-replayed", clause: "§8.3.1.2 (a c_nonce is used once)", code: issuer.ErrorInvalidNonce,
		proofs: func(t *testing.T, f credentialEndpointFixture, n string) map[string][]string {
			if _, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID, Proofs: jwtProofs(proofWith(t, newP256(t), nil, n, nil, nil)), SDJWTClaims: testSDJWTClaims(),
			}); err != nil {
				t.Fatalf("the first request: %v", err)
			}
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, nil))
		}},
	{id: "proof-iss-another-client", clause: "Appendix F.1 (iss is the client_id)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, func(b map[string]any) { b["iss"] = "another-client" }))
		}},
	{id: "proofs-over-the-batch-size", clause: "§8.2 (batch_size)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return jwtProofs(proofWith(t, newP256(t), nil, n, nil, nil), proofWith(t, newP256(t), nil, n, nil, nil), proofWith(t, newP256(t), nil, n, nil, nil))
		}},
	{id: "proofs-an-unsupported-type", clause: "§8.3.1.2 (an unsupported parameter value)", code: issuer.ErrorInvalidCredentialRequest,
		proofs: func(*testing.T, credentialEndpointFixture, string) map[string][]string {
			return map[string][]string{"ldp_vp": {"{}"}}
		}},
	{id: "attestation-by-an-untrusted-key", clause: "Appendix D.1 (key attestation signature)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, _ credentialEndpointFixture, n string) map[string][]string {
			return map[string][]string{oid4vci.ProofTypeAttestation: {buildAttestation(t, newP256(t), n, &newP256(t).PublicKey)}}
		}},
	{id: "attestation-two-of-them", clause: "Appendix F.3 (one key attestation)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, f credentialEndpointFixture, n string) map[string][]string {
			a := buildAttestation(t, f.attestationSigner, n, &newP256(t).PublicKey)
			return map[string][]string{oid4vci.ProofTypeAttestation: {a, a}}
		}},
	{id: "attestation-no-attested-keys", clause: "Appendix D.1 (attested_keys REQUIRED)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, f credentialEndpointFixture, n string) map[string][]string {
			// attestation.Issue won't build one, so it's signed here.
			raw, err := json.Marshal(map[string]any{"iat": time.Now().Unix(), "nonce": n, "attested_keys": []any{}})
			if err != nil {
				t.Fatal(err)
			}
			att, err := jose.Sign(jose.ES256, f.attestationSigner, map[string]any{"typ": attestation.TypHeader}, raw)
			if err != nil {
				t.Fatal(err)
			}
			return map[string][]string{oid4vci.ProofTypeAttestation: {att}}
		}},
	{id: "attestation-expired", clause: "Appendix D.1 (exp)", code: issuer.ErrorInvalidProof,
		proofs: func(t *testing.T, f credentialEndpointFixture, n string) map[string][]string {
			exp := time.Now().Add(-time.Minute).Unix()
			att, err := attestation.Issue(f.attestationSigner, jose.ES256, attestation.Header{}, attestation.Claims{
				IssuedAt: time.Now().Add(-time.Hour).Unix(), ExpiresAt: &exp, AttestedKeys: []json.RawMessage{jwkJSON(t, &newP256(t).PublicKey)}, Nonce: n,
			})
			if err != nil {
				t.Fatal(err)
			}
			return map[string][]string{oid4vci.ProofTypeAttestation: {att}}
		}},
	{id: "attestation-nonce-unknown", clause: "§8.3.1.2 (invalid_nonce)", code: issuer.ErrorInvalidNonce,
		proofs: func(t *testing.T, f credentialEndpointFixture, _ string) map[string][]string {
			return map[string][]string{oid4vci.ProofTypeAttestation: {buildAttestation(t, f.attestationSigner, "not-a-c-nonce", &newP256(t).PublicKey)}}
		}},
}

// Every proof negative vector is refused with its error code; an
// unchanged proof, the control, is accepted.
func TestProofNegativeVectors(t *testing.T) {
	request := func(f credentialEndpointFixture, client string, proofs map[string][]string) error {
		if client == "" {
			client = "test-client"
		}
		_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID(client), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
			CredentialConfigurationID: testSDJWTConfigID, Proofs: proofs, SDJWTClaims: testSDJWTClaims(),
		})
		return err
	}
	control := newCredentialEndpointFixture(t)
	if err := request(control, "", jwtProofs(proofWith(t, newP256(t), nil, control.issueNonce(t), nil, nil))); err != nil {
		t.Fatalf("the jwt control is refused, so no refusal below means anything: %v", err)
	}
	// typ is a media type (RFC 7515 §4.1.9): its application/ form, in
	// any case, names the same one.
	control = newCredentialEndpointFixture(t)
	if err := request(control, "", jwtProofs(proofWith(t, newP256(t), nil, control.issueNonce(t), func(h map[string]any) { h["typ"] = "Application/OpenID4VCI-Proof+JWT" }, nil))); err != nil {
		t.Fatalf("a jwt proof whose typ is in its application/ form is refused: %v", err)
	}
	control = newCredentialEndpointFixture(t)
	n := control.issueNonce(t)
	if err := request(control, "", map[string][]string{oid4vci.ProofTypeAttestation: {buildAttestation(t, control.attestationSigner, n, &newP256(t).PublicKey)}}); err != nil {
		t.Fatalf("the attestation control is refused: %v", err)
	}
	control = newCredentialEndpointFixture(t, withoutNonceEndpoint)
	if err := request(control, "", jwtProofs(proofWith(t, newP256(t), nil, "", nil, func(b map[string]any) { delete(b, "nonce") }))); err != nil {
		t.Fatalf("the control without a Nonce Endpoint is refused: %v", err)
	}
	for _, vec := range proofNegativeVectors {
		t.Run(vec.id, func(t *testing.T) {
			var f credentialEndpointFixture
			nonce := ""
			if vec.noNonceEndpoint {
				f = newCredentialEndpointFixture(t, withoutNonceEndpoint)
			} else {
				f = newCredentialEndpointFixture(t)
				nonce = f.issueNonce(t)
			}
			err := request(f, vec.client, vec.proofs(t, f, nonce))
			var ierr *issuer.Error
			switch {
			case err == nil:
				t.Fatalf("accepted (%s)", vec.clause)
			case !errors.As(err, &ierr) || ierr.Code() != vec.code:
				t.Errorf("refused for another reason: %v, want %q (%s)", err, vec.code, vec.clause)
			}
		})
	}
}
