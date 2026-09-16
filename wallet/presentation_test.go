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
	if len(matches) != 1 || matches["identity_credential"].Credential != fixture.held.Credential {
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

func TestPresentCredentials(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:       testPresentationQuery(t),
		Credentials: []wallet.HeldCredential{fixture.held},
		Audience:    "x509_hash:verifier",
		Nonce:       "nonce-1",
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	if len(vpToken["identity_credential"]) != 1 {
		t.Fatalf("vp_token = %v", vpToken)
	}
	claims, _, err := sdjwtvc.Verify(vpToken["identity_credential"][0], &fixture.issuerKey.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
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
