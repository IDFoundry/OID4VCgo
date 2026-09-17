package verifier_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
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
	return newSDJWTVCPresentationWithIssuer(t, testP256Key(t), aud, nonce)
}

// newSDJWTVCPresentationWithIssuer is newSDJWTVCPresentation with a
// caller-supplied issuerKey instead of a fresh one — lets a test
// build two independent Presentations that share one Issuer key, so a
// single fixedSDJWTVCIssuerKeyResolver can verify both (needed for
// §6.1's own "multiple" — see TestVerifyResponseMultipleVerifiesAllPresentations).
func newSDJWTVCPresentationWithIssuer(t *testing.T, issuerKey *ecdsa.PrivateKey, aud, nonce string) sdjwtVCPresentationFixture {
	t.Helper()
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

// verifySDJWTVCRoundTrip drives a real end-to-end round trip against
// query, via the redirect flow (origin empty) or the DC API flow
// (origin set): build a real Authorization/DC API Request (for its
// own Nonce, and — for the DC API flow — its own "origin:"-prefixed
// audience), issue and present a real SD-JWT VC bound to that exact
// aud/nonce, and verify it via VerifyResponse — the same "real round
// trip, not a simulation" discipline every other cross-package
// wire-format claim in this repo is held to. Shared by
// TestVerifyResponse, TestVerifyResponseAcceptsSatisfiableClaimSetOption,
// and TestVerifyResponseDCAPI, which differ only in which query is
// asked and which flow is exercised.
func verifySDJWTVCRoundTrip(t *testing.T, query dcql.Query, origin string) verifier.VerifiedCredential {
	t.Helper()
	_, _, v := newTestVerifierWithConfig(t)

	var nonce, aud string
	if origin != "" {
		built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
			Query: query, ExpectedOrigins: []string{origin},
		})
		if err != nil {
			t.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
		}
		nonce, aud = built.Nonce, "origin:"+origin
	} else {
		built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
		if err != nil {
			t.Fatalf("BuildAuthorizationRequest: %v", err)
		}
		nonce, aud = built.Nonce, v.ClientID()
	}

	fixture := newSDJWTVCPresentation(t, aud, nonce)

	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
		Origin:        origin,
	})
	return testverify.RequireOneCredential(t, result, err, "identity_credential")
}

func TestVerifyResponse(t *testing.T) {
	vc := verifySDJWTVCRoundTrip(t, testIdentityQuery(t), "")
	if vc.Claims["given_name"] != "Alice" {
		t.Errorf("Claims[given_name] = %v, want Alice", vc.Claims["given_name"])
	}
}

// TestVerifyResponseAcceptsSatisfiableClaimSetOption mirrors §6.4.1's
// own rule on the Verifier side: a Presentation satisfying only the
// second (least-preferred) claim_sets option still verifies — the
// Verifier doesn't require the first option to be the one satisfied,
// just some option.
func TestVerifyResponseAcceptsSatisfiableClaimSetOption(t *testing.T) {
	verifySDJWTVCRoundTrip(t, testverify.ClaimSetOptionsQuery(t, testVCT), "")
}

// TestVerifyResponseDCAPI mirrors TestVerifyResponse for the DC API
// flow: a real "dc+sd-jwt" credential presented with a Key Binding
// JWT bound to the Origin-prefixed audience Appendix A.4 requires
// verifies via the same VerifyResponse, given Origin.
func TestVerifyResponseDCAPI(t *testing.T) {
	vc := verifySDJWTVCRoundTrip(t, testIdentityQuery(t), "https://verifier.example.com")
	if vc.Claims["given_name"] != "Alice" {
		t.Errorf("Claims[given_name] = %v, want Alice", vc.Claims["given_name"])
	}
}

// TestVerifyResponseDCAPIRejectsWrongOrigin mirrors Appendix A.4's own
// rule: a Presentation bound to a different Origin than req.Origin
// fails, the same way a wrong audience fails the redirect flow.
func TestVerifyResponseDCAPIRejectsWrongOrigin(t *testing.T) {
	query := testIdentityQuery(t)
	_, _, v := newTestVerifierWithConfig(t)
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{"https://verifier.example.com"},
	})
	if err != nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}
	fixture := newSDJWTVCPresentation(t, "origin:https://attacker.example.com", built.Nonce)

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
		Origin:        "https://verifier.example.com",
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

// TestVerifyResponseMultipleVerifiesAllPresentations mirrors §6.1's
// own "multiple" field: when a Credential Query has Multiple: true,
// every Presentation in the VP Token's own array for that id is
// verified and returned, not just one.
func TestVerifyResponseMultipleVerifiesAllPresentations(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testVCT),
		Multiple: true,
	}}}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	issuerKey := testP256Key(t)
	fixtureA := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)
	fixtureB := newSDJWTVCPresentationWithIssuer(t, issuerKey, v.ClientID(), built.Nonce)

	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query,
		Response: verifier.ParsedResponse{VPToken: map[string][]string{
			"identity_credential": {fixtureA.compact, fixtureB.compact},
		}},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &issuerKey.PublicKey, alg: jose.ES256},
	})
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	if len(result.Credentials) != 2 {
		t.Fatalf("Credentials = %+v, want 2", result.Credentials)
	}
	for _, vc := range result.Credentials {
		if vc.CredentialQueryID != "identity_credential" {
			t.Errorf("CredentialQueryID = %q, want %q", vc.CredentialQueryID, "identity_credential")
		}
	}
}

// vctCredentialQuery builds a minimal "dc+sd-jwt" Credential Query (no
// Claims/ClaimSets) requiring testVCT — the shape credential_sets
// tests need for each option's own member Credential Queries.
func vctCredentialQuery(t *testing.T, id string) dcql.CredentialQuery {
	t.Helper()
	return dcql.CredentialQuery{ID: id, Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testVCT)}
}

// twoCredentialQueries builds the two-entry Credentials array every
// credential_sets test below needs, one vctCredentialQuery per id.
func twoCredentialQueries(t *testing.T, id1, id2 string) []dcql.CredentialQuery {
	t.Helper()
	return []dcql.CredentialQuery{vctCredentialQuery(t, id1), vctCredentialQuery(t, id2)}
}

// credentialSetsRoundTrip builds a Verifier and one real, verifiable
// SD-JWT VC Presentation, then calls VerifyResponse against query with
// vpToken(compact) as the response's own VP Token — the shared setup
// every credential_sets test needs, differing only in which Credential
// Query id(s) the caller populates the VP Token under.
func credentialSetsRoundTrip(t *testing.T, query dcql.Query, vpToken func(compact string) map[string][]string) (verifier.VerifyResponseResult, error) {
	t.Helper()
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	fixture := newSDJWTVCPresentation(t, v.ClientID(), built.Nonce)
	return v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:         query,
		Response:      verifier.ParsedResponse{VPToken: vpToken(fixture.compact)},
		ExpectedNonce: built.Nonce,
		IssuerKeys:    fixedSDJWTVCIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: jose.ES256},
	})
}

// TestVerifyResponseCredentialSetsPrefersFirstSatisfiableOption
// mirrors §6.4.2's own rule: given a Credential Set Query whose first
// option's Credential Query has no Presentation in the response, the
// second (least-preferred) option still verifies if its own
// Presentation does.
func TestVerifyResponseCredentialSetsPrefersFirstSatisfiableOption(t *testing.T) {
	query := dcql.Query{
		Credentials:    twoCredentialQueries(t, "primary", "secondary"),
		CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"primary"}, {"secondary"}}}},
	}
	result, err := credentialSetsRoundTrip(t, query, func(compact string) map[string][]string {
		return map[string][]string{"secondary": {compact}}
	})
	testverify.RequireOneCredential(t, result, err, "secondary")
}

// TestVerifyResponseCredentialSetsOmitsUnsatisfiedOptionalSet mirrors
// §6.4.2's own rule: a Credential Set Query with required: false and
// no satisfiable option is silently omitted from the result rather
// than failing VerifyResponse entirely.
func TestVerifyResponseCredentialSetsOmitsUnsatisfiedOptionalSet(t *testing.T) {
	falseVal := false
	query := dcql.Query{
		Credentials: twoCredentialQueries(t, "required_cq", "optional_cq"),
		CredentialSets: []dcql.CredentialSetQuery{
			{Options: [][]string{{"required_cq"}}},
			{Required: &falseVal, Options: [][]string{{"optional_cq"}}},
		},
	}
	result, err := credentialSetsRoundTrip(t, query, func(compact string) map[string][]string {
		return map[string][]string{"required_cq": {compact}}
	})
	testverify.RequireOneCredential(t, result, err, "required_cq")
}

// TestVerifyResponseCredentialSetsFailsWhenRequiredSetUnsatisfied
// mirrors §6.4.2's own "MUST NOT return any Credential(s)" rule: a
// required Credential Set Query with no satisfiable option fails
// VerifyResponse entirely, even though another Credential Set Query
// would otherwise be satisfiable.
func TestVerifyResponseCredentialSetsFailsWhenRequiredSetUnsatisfied(t *testing.T) {
	query := dcql.Query{
		Credentials: twoCredentialQueries(t, "unsatisfiable_cq", "satisfiable_cq"),
		CredentialSets: []dcql.CredentialSetQuery{
			{Options: [][]string{{"unsatisfiable_cq"}}},
			{Options: [][]string{{"satisfiable_cq"}}},
		},
	}
	_, err := credentialSetsRoundTrip(t, query, func(compact string) map[string][]string {
		return map[string][]string{"satisfiable_cq": {compact}}
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
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

// TestVerifyResponseRejects table-drives every dc+sd-jwt rejection
// path VerifyResponse covers: a Holder Binding JWT bound to the wrong
// nonce/audience, a Presentation missing a requested claim or carrying
// the wrong vct, no Presentation at all for a Credential Query, an
// unsupported Credential Format, and more than one Presentation for a
// single-valued Credential Query. The mso_mdoc rejection paths have
// their own table in verify_response_mdoc_test.go.
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
			meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{})
			if err != nil {
				t.Fatalf("NewSDJWTVCMeta: %v", err)
			}
			return verifier.VerifyResponseRequest{
				Query:         dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "x", Format: "jwt_vc_json", Meta: meta}}},
				ExpectedNonce: nonce,
				Response:      verifier.ParsedResponse{VPToken: map[string][]string{"x": {"irrelevant"}}},
			}
		},
		"mdoc missing issuer key resolver": func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			return rejectCaseMdocMissingDependency(t, v, nonce, false)
		},
		"mdoc missing response encryption key": func(t *testing.T, v *verifier.Verifier, nonce string) verifier.VerifyResponseRequest {
			return rejectCaseMdocMissingDependency(t, v, nonce, true)
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
