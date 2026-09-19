package wallet_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// newHeldSDJWTVCWithSelectivelyDisclosableClaims is newHeldSDJWTVC's
// own twin, except given_name/family_name are both genuinely
// selectively disclosable (sdjwtvc.SD()) rather than mandatory —
// newHeldSDJWTVC's own fixture never wraps Additional in SD() at all,
// so it has nothing to trim; the tests in this file specifically
// exercise PresentSDJWTVCSelective/PresentCredentials's own trimming,
// which needs real Disclosures to trim from.
func newHeldSDJWTVCWithSelectivelyDisclosableClaims(t *testing.T) heldSDJWTVCFixture {
	t.Helper()
	return newHeldSDJWTVCWithAdditional(t, map[string]any{
		"given_name":  sdjwtvc.SD("Alice"),
		"family_name": sdjwtvc.SD("Doe"),
	})
}

// verifiedSDJWTVCClaims presents/verifies compact against fixture,
// returning the resolved claims — the shared assertion setup every
// test below needs to inspect exactly what a Presentation actually
// discloses.
func verifiedSDJWTVCClaims(t *testing.T, compact string, fixture heldSDJWTVCFixture, aud string) map[string]any {
	t.Helper()
	claims, _, err := sdjwtvc.Verify(compact, &fixture.issuerKey.PublicKey, jose.ES256, sdjwtvc.VerifyOptions{
		RequireKeyBinding: sdjwtvc.KeyBindingRequired,
		HolderPublicKey:   &fixture.holderKey.PublicKey,
		KeyBindingAlg:     jose.ES256,
		ExpectedAudience:  aud,
		ExpectedNonce:     "nonce-1",
		MaxKeyBindingAge:  time.Hour,
	})
	if err != nil {
		t.Fatalf("sdjwtvc.Verify: %v", err)
	}
	return claims
}

// TestPresentSDJWTVCSelectiveTrimsToRequiredPaths mirrors §6.4.1's own
// "the Wallet MUST NOT send selectively disclosable claims that have
// not been selected": asking for only given_name must not disclose
// family_name, even though the held credential carries both.
func TestPresentSDJWTVCSelectiveTrimsToRequiredPaths(t *testing.T) {
	fixture := newHeldSDJWTVCWithSelectivelyDisclosableClaims(t)
	compact, err := wallet.PresentSDJWTVCSelective(fixture.held, "aud", "nonce-1", []dcql.Path{
		{dcql.PathKey("given_name")},
	})
	if err != nil {
		t.Fatalf("PresentSDJWTVCSelective: %v", err)
	}
	claims := verifiedSDJWTVCClaims(t, compact, fixture, "aud")
	if claims["given_name"] != "Alice" {
		t.Errorf("given_name = %v, want Alice", claims["given_name"])
	}
	if _, hasFamilyName := claims["family_name"]; hasFamilyName {
		t.Errorf("claims discloses family_name, which wasn't in requiredPaths: %v", claims)
	}
}

// TestPresentSDJWTVCSelectiveEmptyPathsDisclosesNothingSelective
// mirrors §6.4.1's own "claims is absent" default: no requiredPaths
// means no selectively disclosable claim comes through at all.
func TestPresentSDJWTVCSelectiveEmptyPathsDisclosesNothingSelective(t *testing.T) {
	fixture := newHeldSDJWTVCWithSelectivelyDisclosableClaims(t)
	compact, err := wallet.PresentSDJWTVCSelective(fixture.held, "aud", "nonce-1", nil)
	if err != nil {
		t.Fatalf("PresentSDJWTVCSelective: %v", err)
	}
	claims := verifiedSDJWTVCClaims(t, compact, fixture, "aud")
	if _, has := claims["given_name"]; has {
		t.Errorf("claims discloses given_name with an empty requiredPaths: %v", claims)
	}
	if _, has := claims["family_name"]; has {
		t.Errorf("claims discloses family_name with an empty requiredPaths: %v", claims)
	}
}

// TestPresentSDJWTVCSelectiveFallsBackForNonKeyPath checks
// PresentSDJWTVCSelective's own documented fallback: a Path containing
// a Wildcard component isn't supported for trimming, so every
// Disclosure is included instead of guessing.
// TestPresentSDJWTVCSelectiveRejectsNonKeyPath is the regression test
// for a real bug found in a repo-wide security review: an earlier
// version of PresentSDJWTVCSelective silently fell back to disclosing
// every Disclosure in the credential when given a Claims Path it
// couldn't trim against (a Wildcard/Index component) — a real
// over-disclosure of undisclosed claims, not a graceful degradation
// (§6.4.1's own "MUST NOT send claims that have not been selected").
// It must now fail loudly instead.
func TestPresentSDJWTVCSelectiveRejectsNonKeyPath(t *testing.T) {
	fixture := newHeldSDJWTVCWithSelectivelyDisclosableClaims(t)
	_, err := wallet.PresentSDJWTVCSelective(fixture.held, "aud", "nonce-1", []dcql.Path{
		{dcql.PathKey("given_name"), dcql.Wildcard},
	})
	if err == nil {
		t.Fatal("PresentSDJWTVCSelective = nil error, want an error (must not silently fall back to full disclosure)")
	}
}

// TestPresentCredentialsTrimsToMatchedCredentialQuery drives the same
// trimming through the full PresentCredentials pipeline: a query
// asking only for given_name, against a held credential that also
// carries a selectively disclosable family_name, must not disclose
// family_name in the resulting vp_token.
func TestPresentCredentialsTrimsToMatchedCredentialQuery(t *testing.T) {
	fixture := newHeldSDJWTVCWithSelectivelyDisclosableClaims(t)
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
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
	claims := verifiedSDJWTVCClaims(t, vpToken["identity_credential"][0], fixture, "x509_hash:verifier")
	if claims["given_name"] != "Alice" {
		t.Errorf("given_name = %v, want Alice", claims["given_name"])
	}
	if _, hasFamilyName := claims["family_name"]; hasFamilyName {
		t.Errorf("vp_token discloses family_name, which testPresentationQuery never asked for: %v", claims)
	}
}
