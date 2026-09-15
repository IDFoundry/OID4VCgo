package verifier_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/verifier"
)

const testVCT = "https://credentials.example.com/identity_credential"

// fixedSDJWTVCIssuerKeyResolver always resolves to the one issuer key
// a test signed with — standing in for whatever real trust mechanism
// (x5c chain validation against trusted_authorities) a deployment
// would use, exactly like issuer.AttestationVerifier's own test
// fakes.
type fixedSDJWTVCIssuerKeyResolver struct {
	pub crypto.PublicKey
	alg jose.Alg
}

func (r fixedSDJWTVCIssuerKeyResolver) ResolveIssuerKey(context.Context, map[string]any, map[string]any) (crypto.PublicKey, jose.Alg, error) {
	return r.pub, r.alg, nil
}

func jwkFromECDSA(pub *ecdsa.PublicKey) (map[string]any, error) {
	raw, err := pub.Bytes()
	if err != nil {
		return nil, err
	}
	size := (len(raw) - 1) / 2
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": enc(raw[1 : 1+size]), "y": enc(raw[1+size:]),
	}, nil
}

// sdjwtVCPresentationFixture is a real, fully issued and presented
// "dc+sd-jwt" credential — the setup every VerifyResponse test needs,
// parameterized only by the aud/nonce its own Key Binding JWT is
// signed over (so tests can build one with a deliberately wrong
// value).
type sdjwtVCPresentationFixture struct {
	issuerKey *ecdsa.PrivateKey
	holderKey *ecdsa.PrivateKey
	compact   string
}

func newSDJWTVCPresentation(t *testing.T, aud, nonce string) sdjwtVCPresentationFixture {
	t.Helper()
	issuerKey := testP256Key(t)
	holderKey := testP256Key(t)

	holderJWK, err := jwkFromECDSA(&holderKey.PublicKey)
	if err != nil {
		t.Fatalf("jwkFromECDSA: %v", err)
	}
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: testVCT,
		CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"given_name": "Alice",
		},
	}, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	pres, err := sdjwtvc.Parse(sdjwt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	kbJWT, err := sdjwtvc.NewKeyBindingJWT(holderKey, jose.ES256, pres, sdjwtvc.SHA256, sdjwtvc.KeyBindingClaims{
		Audience: aud, Nonce: nonce,
	})
	if err != nil {
		t.Fatalf("NewKeyBindingJWT: %v", err)
	}
	pres.KeyBindingJWT = kbJWT
	compact, err := pres.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	return sdjwtVCPresentationFixture{issuerKey: issuerKey, holderKey: holderKey, compact: compact}
}

func testIdentityQuery(t *testing.T) dcql.Query {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{testVCT}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return dcql.Query{
		Credentials: []dcql.CredentialQuery{{
			ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta,
			Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
		}},
	}
}

// TestVerifyResponse drives a real end-to-end round trip: build a real
// Authorization Request (for its own ClientID/Nonce), issue and
// present a real SD-JWT VC bound to that exact aud/nonce, and verify
// it via VerifyResponse — the same "real round trip, not a
// simulation" discipline every other cross-package wire-format claim
// in this repo is held to.
func TestVerifyResponse(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	query := testIdentityQuery(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	fixture := newSDJWTVCPresentation(t, v.ClientID(), built.Nonce)

	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(result.Credentials))
	}
	if result.Credentials[0].CredentialQueryID != "identity_credential" {
		t.Errorf("CredentialQueryID = %q", result.Credentials[0].CredentialQueryID)
	}
	if result.Credentials[0].Claims["given_name"] != "Alice" {
		t.Errorf("Claims[given_name] = %v, want Alice", result.Credentials[0].Claims["given_name"])
	}
}

// rejectCaseSDJWTVC builds a VerifyResponseRequest presenting one real
// SD-JWT VC (bound to presAud/presNonce) against query, expecting
// expectedNonce — the shared shape most of TestVerifyResponseRejects's
// own cases need, varying only which of those four diverge from a
// valid request.
func rejectCaseSDJWTVC(t *testing.T, query dcql.Query, presAud, presNonce, expectedNonce string) verifier.VerifyResponseRequest {
	t.Helper()
	fixture := newSDJWTVCPresentation(t, presAud, presNonce)
	return verifier.VerifyResponseRequest{
		Query: query, ExpectedNonce: expectedNonce,
		Response:   verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		IssuerKeys: fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	}
}

// TestVerifyResponseRejects table-drives every rejection path
// VerifyResponse's own Phase 2a scope covers: a Holder Binding JWT
// bound to the wrong nonce/audience, a Presentation missing a
// requested claim or carrying the wrong vct, no Presentation at all
// for a Credential Query, an unsupported Credential Format, and more
// than one Presentation for a single-valued Credential Query.
func TestVerifyResponseRejects(t *testing.T) {
	cases := map[string]func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest{
		"wrong nonce": func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			return rejectCaseSDJWTVC(t, testIdentityQuery(t), v.ClientID(), "wrong-nonce", nonce)
		},
		"wrong audience": func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			return rejectCaseSDJWTVC(t, testIdentityQuery(t), "x509_hash:not-this-verifier", nonce, nonce)
		},
		"missing requested claim": func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{testVCT}})
			if err != nil {
				t.Fatalf("NewSDJWTVCMeta: %v", err)
			}
			query := dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta,
				Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("no_such_claim")}}},
			}}}
			return rejectCaseSDJWTVC(t, query, v.ClientID(), nonce, nonce)
		},
		"wrong vct": func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"https://credentials.example.com/some_other_credential"}})
			if err != nil {
				t.Fatalf("NewSDJWTVCMeta: %v", err)
			}
			query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta}}}
			return rejectCaseSDJWTVC(t, query, v.ClientID(), nonce, nonce)
		},
		"missing presentation": func(t *testing.T, _ *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			return verifier.VerifyResponseRequest{
				Query: testIdentityQuery(t), ExpectedNonce: nonce,
				Response: verifier.ParsedResponse{VPToken: map[string][]string{}},
			}
		},
		"unsupported format": func(t *testing.T, _ *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: "org.iso.18013.5.1.mDL"})
			if err != nil {
				t.Fatalf("NewMdocMeta: %v", err)
			}
			return verifier.VerifyResponseRequest{
				Query:         dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "mdl", Format: "mso_mdoc", Meta: meta}}},
				ExpectedNonce: nonce,
				Response:      verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {"base64url-device-response"}}},
			}
		},
		"multiple presentations": func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			fixture := newSDJWTVCPresentation(t, v.ClientID(), nonce)
			return verifier.VerifyResponseRequest{
				Query: testIdentityQuery(t), ExpectedNonce: nonce,
				Response:   verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact, fixture.compact}}},
				IssuerKeys: fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, deps := validConfig(t)
			v, err := verifier.New(cfg, deps)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testIdentityQuery(t)})
			if err != nil {
				t.Fatalf("BuildAuthorizationRequest: %v", err)
			}
			req := setup(t, v, built.Nonce)
			if _, err := v.VerifyResponse(context.Background(), req); err == nil {
				t.Fatalf("VerifyResponse(%s) = nil error, want error", name)
			}
		})
	}
}
