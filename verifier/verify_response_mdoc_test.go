package verifier_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// fixedMdocIssuerKeyResolver always resolves to the one issuer key a
// test signed with — the mdoc analog of fixedSDJWTVCIssuerKeyResolver.
type fixedMdocIssuerKeyResolver struct {
	pub crypto.PublicKey
	alg cose.Alg
}

func (r fixedMdocIssuerKeyResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, cose.Alg, error) {
	return r.pub, r.alg, nil
}

// mdocVerifyFixture bundles a real *verifier.Verifier, the DCQL query
// it was given, the Nonce/ResponseDecryptionKey a prior Build*Request
// call returned, and a real issued "mso_mdoc" credential's own
// response-encryption thumbprint — the setup every VerifyResponse
// mdoc test needs before building its own Presentation with whichever
// aud/nonce that specific case wants. Origin is empty for the
// redirect flow (newMdocVerifyFixture), set for the DC API flow
// (newMdocDCAPIVerifyFixture) — verify's own single implementation
// dispatches on it rather than each flow needing its own copy.
type mdocVerifyFixture struct {
	v                     *verifier.Verifier
	cfg                   verifier.Config
	query                 dcql.Query
	nonce                 string
	responseDecryptionKey *ecdsa.PrivateKey
	thumbprint            []byte
	f                     testmdoc.Fixture
	origin                string
}

func newMdocVerifyFixture(t *testing.T) mdocVerifyFixture {
	t.Helper()
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	query := testmdoc.Query(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	return newMdocVerifyFixtureFromKey(t, v, cfg, query, built.Nonce, built.ResponseDecryptionKey, "")
}

// newMdocDCAPIVerifyFixture is newMdocVerifyFixture's own DC API
// counterpart, built via BuildDCAPIAuthorizationRequest instead.
func newMdocDCAPIVerifyFixture(t *testing.T) mdocVerifyFixture {
	t.Helper()
	v := newTestVerifier(t)
	query := testmdoc.Query(t)
	origin := "https://verifier.example.com"
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{origin},
	})
	if err != nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}
	return newMdocVerifyFixtureFromKey(t, v, verifier.Config{}, query, built.Nonce, built.ResponseDecryptionKey, origin)
}

func newMdocVerifyFixtureFromKey(t *testing.T, v *verifier.Verifier, cfg verifier.Config, query dcql.Query, nonce string, responseDecryptionKey *ecdsa.PrivateKey, origin string) mdocVerifyFixture {
	t.Helper()
	thumbprint := testmdoc.ResponseEncryptionThumbprint(t, responseDecryptionKey)
	f := testmdoc.Issue(t)
	return mdocVerifyFixture{
		v: v, cfg: cfg, query: query, nonce: nonce, responseDecryptionKey: responseDecryptionKey,
		thumbprint: thumbprint, f: f, origin: origin,
	}
}

// verify builds a Presentation bound to nonce (not necessarily
// mf.nonce — a test deliberately mismatching it uses this to build
// one that won't validate) and calls VerifyResponse with it, via
// whichever flow mf.origin selects.
func (mf mdocVerifyFixture) verify(t *testing.T, nonce string) (verifier.VerifyResponseResult, error) {
	t.Helper()
	var presented string
	if mf.origin != "" {
		presented = testmdoc.PresentDCAPI(t, mf.f, oid4vpmdoc.DCAPIHandoverParams{
			Origin: mf.origin, Nonce: nonce, ResponseEncryptionJWKThumbprint: mf.thumbprint,
		})
	} else {
		presented = testmdoc.Present(t, mf.f, oid4vpmdoc.HandoverParams{
			ClientID: mf.v.ClientID(), Nonce: nonce, ResponseURI: mf.cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: mf.thumbprint,
		})
	}
	return mf.v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 mf.query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {presented}}},
		ExpectedNonce:         mf.nonce,
		MdocIssuerKeys:        fixedMdocIssuerKeyResolver{pub: &mf.f.IssuerKey.PublicKey, alg: cose.ES256},
		ResponseEncryptionKey: mf.responseDecryptionKey,
		Origin:                mf.origin,
	})
}

// assertMdocGivenNameAlice asserts a successful VerifyResponse call
// returned exactly one "mdl" VerifiedCredential whose own
// org.iso.18013.5.1 namespace carries given_name "Alice" —
// testmdoc.Issue's own fixed claim — shared by TestVerifyMdocResponse
// and TestVerifyMdocResponseDCAPI, which differ only in which flow
// mf's own fixture exercises.
func assertMdocGivenNameAlice(t *testing.T, result verifier.VerifyResponseResult, err error) {
	t.Helper()
	vc := testverify.RequireOneCredential(t, result, err, "mdl")
	namespace, ok := vc.Claims["org.iso.18013.5.1"].(map[string]interface{})
	if !ok || namespace["given_name"] != "Alice" {
		t.Errorf("Claims[org.iso.18013.5.1] = %v", vc.Claims["org.iso.18013.5.1"])
	}
}

// TestVerifyMdocResponse drives a real end-to-end round trip: build a
// real Authorization Request, issue and present a real "mso_mdoc"
// credential bound to that exact clientID/nonce/responseURI/response-
// encryption-key thumbprint, and verify it via VerifyResponse.
func TestVerifyMdocResponse(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	result, err := mf.verify(t, mf.nonce)
	assertMdocGivenNameAlice(t, result, err)
}

func TestVerifyMdocResponseRejectsWrongNonce(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	if _, err := mf.verify(t, "wrong-nonce"); err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

// TestVerifyMdocResponseDCAPI mirrors TestVerifyMdocResponse for the
// DC API flow: a real "mso_mdoc" credential presented with a
// DC-API-shaped SessionTranscript (Appendix B.2.6.2, origin-bound)
// verifies via the same VerifyResponse, given Origin.
func TestVerifyMdocResponseDCAPI(t *testing.T) {
	mf := newMdocDCAPIVerifyFixture(t)
	result, err := mf.verify(t, mf.nonce)
	assertMdocGivenNameAlice(t, result, err)
}

func TestVerifyMdocResponseDCAPIRejectsWrongNonce(t *testing.T) {
	mf := newMdocDCAPIVerifyFixture(t)
	if _, err := mf.verify(t, "wrong-nonce"); err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

// rejectCaseMdocMissingDependency builds a VerifyResponseRequest for
// testmdoc.Query missing exactly one of MdocIssuerKeys/
// ResponseEncryptionKey — both are checked before the (irrelevant
// here) presented content is even decoded, so a placeholder string is
// enough.
func rejectCaseMdocMissingDependency(t *testing.T, v *verifier.Verifier, nonce string, missingResponseEncryptionKey bool) verifier.VerifyResponseRequest {
	t.Helper()
	req := verifier.VerifyResponseRequest{
		Query: testmdoc.Query(t), ExpectedNonce: nonce,
		Response: verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {"irrelevant"}}},
	}
	if missingResponseEncryptionKey {
		req.MdocIssuerKeys = fixedMdocIssuerKeyResolver{}
	} else {
		req.ResponseEncryptionKey = testP256Key(t)
	}
	return req
}
