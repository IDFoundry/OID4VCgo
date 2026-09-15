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

func TestVerifyResponseRejectsWrongNonce(t *testing.T) {
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
	fixture := newSDJWTVCPresentation(t, v.ClientID(), "wrong-nonce")

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

func TestVerifyResponseRejectsWrongAudience(t *testing.T) {
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
	fixture := newSDJWTVCPresentation(t, "x509_hash:not-this-verifier", built.Nonce)

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

func TestVerifyResponseRejectsMissingRequestedClaim(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{testVCT}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("no_such_claim")}}},
	}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	fixture := newSDJWTVCPresentation(t, v.ClientID(), built.Nonce)

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

func TestVerifyResponseRejectsWrongVCT(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"https://credentials.example.com/some_other_credential"}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta,
	}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	fixture := newSDJWTVCPresentation(t, v.ClientID(), built.Nonce)

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

func TestVerifyResponseRejectsMissingPresentation(t *testing.T) {
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

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{}},
		ExpectedNonce: built.Nonce,
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

func TestVerifyResponseRejectsUnsupportedFormat(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: "org.iso.18013.5.1.mDL"})
	if err != nil {
		t.Fatalf("NewMdocMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "mdl", Format: "mso_mdoc", Meta: meta}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {"base64url-device-response"}}},
		ExpectedNonce: built.Nonce,
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

func TestVerifyResponseRejectsMultiplePresentations(t *testing.T) {
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

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query,
		Response: verifier.ParsedResponse{
			VPToken: map[string][]string{"identity_credential": {fixture.compact, fixture.compact}},
		},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}
