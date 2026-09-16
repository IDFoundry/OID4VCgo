package wallet_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/internal/testverify"
	"github.com/idfoundry/oid4vcigo/wallet"
)

const testPresentationVCT = "https://credentials.example.com/identity_credential"

// presentationJWKMap encodes pub as a plain map[string]any — the shape
// sdjwtvc.Claims.CNF's own "jwk" member needs — reusing internal/jwk's
// own Marshal rather than hand-rolling EC point encoding again.
func presentationJWKMap(t *testing.T, pub *ecdsa.PublicKey) map[string]any {
	t.Helper()
	j, err := jwk.Marshal(pub)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	return m
}

// heldSDJWTVCFixture is a real, freshly issued "dc+sd-jwt" credential
// bound to a fresh holder key, wrapped as a wallet.HeldCredential —
// the setup every MatchDCQLQuery/PresentSDJWTVC/PresentCredentials
// test needs.
type heldSDJWTVCFixture struct {
	issuerKey *ecdsa.PrivateKey
	holderKey *ecdsa.PrivateKey
	held      wallet.HeldCredential
}

func newHeldSDJWTVC(t *testing.T) heldSDJWTVCFixture {
	t.Helper()
	issuerKey := testP256Key(t)
	holderKey := testP256Key(t)
	holderJWK := presentationJWKMap(t, &holderKey.PublicKey)
	sdjwt, _, err := sdjwtvc.Issue(issuerKey, jose.ES256, sdjwtvc.Claims{
		VCT: testPresentationVCT,
		CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"given_name": "Alice",
		},
	}, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return heldSDJWTVCFixture{
		issuerKey: issuerKey, holderKey: holderKey,
		held: wallet.HeldCredential{
			Format: sdjwtvc.CredentialFormat, Credential: sdjwt,
			HolderKey: holderKey, HolderKeyAlg: jose.ES256,
		},
	}
}

func testPresentationQuery(t *testing.T) dcql.Query {
	t.Helper()
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testPresentationVCT),
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
	}}}
}

// matchesOneCredential asserts a successful MatchDCQLQuery call
// (against fixture.held) matched exactly the "identity_credential"
// query with fixture's own credential — shared by TestMatchDCQLQuery
// and TestMatchDCQLQueryAcceptsSatisfiableClaimSetOption, which differ
// only in which query is asked.
func matchesOneCredential(t *testing.T, query dcql.Query, fixture heldSDJWTVCFixture) {
	t.Helper()
	matches, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches) != 1 || len(matches["identity_credential"]) != 1 || matches["identity_credential"][0].Credential != fixture.held.Credential {
		t.Errorf("matches = %+v", matches)
	}
}

func TestMatchDCQLQuery(t *testing.T) {
	matchesOneCredential(t, testPresentationQuery(t), newHeldSDJWTVC(t))
}

func TestMatchDCQLQueryRejectsNoCandidate(t *testing.T) {
	if _, err := wallet.MatchDCQLQuery(testPresentationQuery(t), nil); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

func TestMatchDCQLQueryRejectsWrongVCT(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	meta := testverify.MustSDJWTVCMeta(t, "https://credentials.example.com/some_other_credential")
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "x", Format: sdjwtvc.CredentialFormat, Meta: meta}}}
	if _, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held}); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

// TestMatchDCQLQueryAcceptsSatisfiableClaimSetOption mirrors §6.4.1's
// own rule: given two alternative claim_sets options, a held
// credential that can only satisfy the second (least-preferred) one
// still matches — the Wallet doesn't require the first option to be
// satisfiable, just some option.
func TestMatchDCQLQueryAcceptsSatisfiableClaimSetOption(t *testing.T) {
	matchesOneCredential(t, testverify.ClaimSetOptionsQuery(t, testPresentationVCT), newHeldSDJWTVC(t))
}

func TestMatchDCQLQueryRejectsWhenNoClaimSetOptionSatisfied(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testPresentationVCT),
		Claims:    []dcql.ClaimsQuery{{ID: "no_such_claim", Path: dcql.Path{dcql.PathKey("no_such_claim")}}},
		ClaimSets: [][]string{{"no_such_claim"}},
	}}}
	if _, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held}); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

// vctCredentialQuery builds a minimal "dc+sd-jwt" Credential Query
// (no Claims/ClaimSets) constrained to vct — the shape
// credential_sets tests need for each option's own member Credential
// Queries.
func vctCredentialQuery(t *testing.T, id, vct string) dcql.CredentialQuery {
	t.Helper()
	return dcql.CredentialQuery{ID: id, Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, vct)}
}

// twoVCTCredentials builds the two-entry Credentials array every
// credential_sets test below needs, one vctCredentialQuery per
// id/vct pair.
func twoVCTCredentials(t *testing.T, id1, vct1, id2, vct2 string) []dcql.CredentialQuery {
	t.Helper()
	return []dcql.CredentialQuery{vctCredentialQuery(t, id1, vct1), vctCredentialQuery(t, id2, vct2)}
}

const otherVCT = "https://credentials.example.com/other_credential"

// TestMatchDCQLQueryCredentialSetsPrefersFirstSatisfiableOption
// mirrors §6.4.2's own rule: given a Credential Set Query whose first
// option's Credential Query no candidate satisfies, the second
// (least-preferred) option still wins the match if it's satisfiable.
func TestMatchDCQLQueryCredentialSetsPrefersFirstSatisfiableOption(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	query := dcql.Query{
		Credentials:    twoVCTCredentials(t, "primary", otherVCT, "secondary", testPresentationVCT),
		CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"primary"}, {"secondary"}}}},
	}
	matches, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches) != 1 || len(matches["secondary"]) != 1 || matches["secondary"][0].Credential != fixture.held.Credential {
		t.Errorf("matches = %+v, want only %q", matches, "secondary")
	}
}

// TestMatchDCQLQueryCredentialSetsOmitsUnsatisfiedOptionalSet mirrors
// §6.4.2's own rule: a Credential Set Query with required: false and
// no satisfiable option is silently omitted from the result rather
// than failing the whole match.
func TestMatchDCQLQueryCredentialSetsOmitsUnsatisfiedOptionalSet(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	falseVal := false
	query := dcql.Query{
		Credentials: twoVCTCredentials(t, "required_cq", testPresentationVCT, "optional_cq", otherVCT),
		CredentialSets: []dcql.CredentialSetQuery{
			{Options: [][]string{{"required_cq"}}},
			{Required: &falseVal, Options: [][]string{{"optional_cq"}}},
		},
	}
	matches, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches) != 1 || len(matches["required_cq"]) != 1 || matches["required_cq"][0].Credential != fixture.held.Credential {
		t.Errorf("matches = %+v, want only %q", matches, "required_cq")
	}
}

// TestMatchDCQLQueryCredentialSetsFailsWhenRequiredSetUnsatisfied
// mirrors §6.4.2's own "MUST NOT return any Credential(s)" rule: a
// required Credential Set Query with no satisfiable option fails the
// whole match, even though other Credential Set Queries would
// otherwise be satisfiable.
func TestMatchDCQLQueryCredentialSetsFailsWhenRequiredSetUnsatisfied(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	query := dcql.Query{
		Credentials: twoVCTCredentials(t, "unsatisfiable_cq", otherVCT, "satisfiable_cq", testPresentationVCT),
		CredentialSets: []dcql.CredentialSetQuery{
			{Options: [][]string{{"unsatisfiable_cq"}}},
			{Options: [][]string{{"satisfiable_cq"}}},
		},
	}
	if _, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held}); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

// multipleIdentityCredentialQuery is testPresentationQuery's own
// Multiple: true twin (no Claims — the multiple tests below only care
// about how many HeldCredentials/Presentations come back, not which
// claims) — shared by every test exercising §6.1's own "multiple"
// field.
func multipleIdentityCredentialQuery(t *testing.T) dcql.Query {
	t.Helper()
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: testverify.MustSDJWTVCMeta(t, testPresentationVCT),
		Multiple: true,
	}}}
}

// TestMatchDCQLQueryMultipleReturnsAllCandidates mirrors §6.1's own
// "multiple" field: when true, every candidate satisfying the
// Credential Query is returned, not just the first.
func TestMatchDCQLQueryMultipleReturnsAllCandidates(t *testing.T) {
	fixtureA := newHeldSDJWTVC(t)
	fixtureB := newHeldSDJWTVC(t)
	matches, err := wallet.MatchDCQLQuery(multipleIdentityCredentialQuery(t), []wallet.HeldCredential{fixtureA.held, fixtureB.held})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches["identity_credential"]) != 2 {
		t.Errorf("matches[identity_credential] = %+v, want 2 entries", matches["identity_credential"])
	}
}

// TestMatchDCQLQueryWithoutMultipleReturnsOnlyOneCandidate mirrors
// §6.1's own default: even when two candidates could both satisfy a
// Credential Query, Multiple defaulting to false means only one is
// returned.
func TestMatchDCQLQueryWithoutMultipleReturnsOnlyOneCandidate(t *testing.T) {
	fixtureA := newHeldSDJWTVC(t)
	fixtureB := newHeldSDJWTVC(t)
	matches, err := wallet.MatchDCQLQuery(testPresentationQuery(t), []wallet.HeldCredential{fixtureA.held, fixtureB.held})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches["identity_credential"]) != 1 {
		t.Errorf("matches[identity_credential] = %+v, want exactly 1 entry", matches["identity_credential"])
	}
}

func TestMatchDCQLQueryRejectsInvalidQuery(t *testing.T) {
	if _, err := wallet.MatchDCQLQuery(dcql.Query{}, nil); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

func TestPresentSDJWTVC(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	compact, err := wallet.PresentSDJWTVC(fixture.held, "x509_hash:verifier", "nonce-1")
	if err != nil {
		t.Fatalf("PresentSDJWTVC: %v", err)
	}
	claims, _, err := sdjwtvc.Verify(compact, &fixture.issuerKey.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: true,
		HolderPublicKey:   &fixture.holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  "x509_hash:verifier",
		ExpectedNonce:     "nonce-1",
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if claims["given_name"] != "Alice" {
		t.Errorf("given_name = %v, want Alice", claims["given_name"])
	}
}

func TestPresentSDJWTVCRejectsWrongFormat(t *testing.T) {
	held := wallet.HeldCredential{Format: "mso_mdoc", Credential: "irrelevant"}
	if _, err := wallet.PresentSDJWTVC(held, "aud", "nonce"); err == nil {
		t.Fatalf("PresentSDJWTVC = nil error, want error")
	}
}

// assertPresentedSDJWTVC verifies presented (a PresentCredentials/
// PresentSDJWTVC result) against wantAudience/wantNonce and checks its
// own given_name — shared by TestPresentCredentials/
// TestPresentCredentialsDCAPI, which differ only in which audience
// they expect (this Verifier's own Client Identifier vs. Appendix
// A.4's own "origin:"-prefixed value).
func assertPresentedSDJWTVC(t *testing.T, presented string, fixture heldSDJWTVCFixture, wantAudience, wantNonce string) {
	t.Helper()
	claims, _, err := sdjwtvc.Verify(presented, &fixture.issuerKey.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: true,
		HolderPublicKey:   &fixture.holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  wantAudience,
		ExpectedNonce:     wantNonce,
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	if claims["given_name"] != "Alice" {
		t.Errorf("given_name = %v, want Alice", claims["given_name"])
	}
}

// presentIdentityCredential calls PresentCredentials for
// testPresentationQuery/fixture with the given audience/origin
// (exactly one non-empty), asserts exactly one Presentation came back,
// and returns the resulting vp_token — shared by TestPresentCredentials
// and TestPresentCredentialsDCAPI, which differ only in which of
// audience/origin they pass.
func presentIdentityCredential(t *testing.T, fixture heldSDJWTVCFixture, audience, origin string) map[string][]string {
	t.Helper()
	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:       testPresentationQuery(t),
		Credentials: []wallet.HeldCredential{fixture.held},
		Audience:    audience, Origin: origin,
		Nonce: "nonce-1",
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	if len(vpToken["identity_credential"]) != 1 {
		t.Fatalf("vp_token = %v", vpToken)
	}
	return vpToken
}

func TestPresentCredentials(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	vpToken := presentIdentityCredential(t, fixture, "x509_hash:verifier", "")
	assertPresentedSDJWTVC(t, vpToken["identity_credential"][0], fixture, "x509_hash:verifier", "nonce-1")
}

// TestPresentCredentialsDCAPI mirrors TestPresentCredentials for the
// DC API flow: PresentationRequest.Origin set binds the resulting Key
// Binding JWT to Appendix A.4's own "origin:"-prefixed audience
// instead of Audience.
func TestPresentCredentialsDCAPI(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	vpToken := presentIdentityCredential(t, fixture, "", "https://verifier.example.com")
	assertPresentedSDJWTVC(t, vpToken["identity_credential"][0], fixture, "origin:https://verifier.example.com", "nonce-1")
}

// TestPresentCredentialsMultiple mirrors §6.1's own "multiple" field
// on the full PresentCredentials pipeline: a Multiple Credential
// Query with two satisfying candidates yields two Presentations in
// the vp_token's own array, §8.1's own "an array of one or more
// Presentations".
func TestPresentCredentialsMultiple(t *testing.T) {
	fixtureA := newHeldSDJWTVC(t)
	fixtureB := newHeldSDJWTVC(t)
	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:       multipleIdentityCredentialQuery(t),
		Credentials: []wallet.HeldCredential{fixtureA.held, fixtureB.held},
		Audience:    "x509_hash:verifier",
		Nonce:       "nonce-1",
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	if len(vpToken["identity_credential"]) != 2 {
		t.Fatalf("vp_token = %v", vpToken)
	}
}

func TestPresentCredentialsRejectsMissingAudienceOrNonce(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	cases := map[string]wallet.PresentationRequest{
		"missing audience": {Query: testPresentationQuery(t), Credentials: []wallet.HeldCredential{fixture.held}, Nonce: "nonce-1"},
		"missing nonce":    {Query: testPresentationQuery(t), Credentials: []wallet.HeldCredential{fixture.held}, Audience: "x509_hash:verifier"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := wallet.PresentCredentials(req); err == nil {
				t.Fatalf("PresentCredentials(%s) = nil error, want error", name)
			}
		})
	}
}
