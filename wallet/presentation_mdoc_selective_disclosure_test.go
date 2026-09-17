package wallet_test

import (
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// mdocSelectiveParams is the PresentMdocParams every test in this file
// shares — the redirect flow, matching TestPresentMdoc's own choice.
func mdocSelectiveParams() wallet.PresentMdocParams {
	return wallet.PresentMdocParams{
		Audience: "x509_hash:verifier", Nonce: "nonce-1",
		ResponseURI: "https://verifier.example.com/response", ResponseEncryptionJWKThumbprint: make([]byte, 32),
	}
}

// decodePresentedMdocNameSpaces decodes presented (a
// wallet.PresentMdoc/PresentMdocSelective result) and returns its own
// disclosed IssuerSigned namespace/element identifiers — what the
// tests in this file inspect to check trimming, without needing a full
// mdoc.Verify (this package never verifies a held credential's own
// Issuer signature, see HeldCredential's own doc comment).
func decodePresentedMdocNameSpaces(t *testing.T, presented string) map[string][]string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		t.Fatalf("UnmarshalDeviceResponse: %v", err)
	}
	out := make(map[string][]string, len(doc.IssuerSigned.NameSpaces))
	for namespace, items := range doc.IssuerSigned.NameSpaces {
		elements := make([]string, len(items))
		for i, item := range items {
			elements[i] = item.ElementIdentifier
		}
		out[namespace] = elements
	}
	return out
}

// TestPresentMdocSelectiveTrimsToRequiredPaths mirrors the "dc+sd-jwt"
// side's own TestPresentSDJWTVCSelectiveTrimsToRequiredPaths: asking
// for only given_name must not disclose family_name, even though the
// held credential carries both (testmdoc.Issue's own fixture).
func TestPresentMdocSelectiveTrimsToRequiredPaths(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)

	presented, err := wallet.PresentMdocSelective(held, mdocSelectiveParams(), []dcql.Path{
		{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("given_name")},
	})
	if err != nil {
		t.Fatalf("PresentMdocSelective: %v", err)
	}

	nameSpaces := decodePresentedMdocNameSpaces(t, presented)
	elements := nameSpaces["org.iso.18013.5.1"]
	if len(elements) != 1 || elements[0] != "given_name" {
		t.Errorf("org.iso.18013.5.1 elements = %v, want exactly [given_name]", elements)
	}
}

// TestPresentMdocSelectiveEmptyPathsDisclosesNothing mirrors §6.4.1's
// own "claims is absent" default for the mdoc side: unlike "dc+sd-jwt",
// mdoc has no notion of claims that are mandatory regardless of what
// was requested, so an empty requiredPaths discloses nothing at all.
func TestPresentMdocSelectiveEmptyPathsDisclosesNothing(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)

	presented, err := wallet.PresentMdocSelective(held, mdocSelectiveParams(), nil)
	if err != nil {
		t.Fatalf("PresentMdocSelective: %v", err)
	}

	nameSpaces := decodePresentedMdocNameSpaces(t, presented)
	if len(nameSpaces) != 0 {
		t.Errorf("nameSpaces = %v, want empty", nameSpaces)
	}
}

// TestPresentMdocSelectiveFallsBackForNonMdocPath checks
// PresentMdocSelective's own documented fallback: a Path that isn't a
// valid two-component mdoc-form path (here, a three-component one)
// isn't supported for trimming, so every namespace/element is included
// instead of guessing.
func TestPresentMdocSelectiveFallsBackForNonMdocPath(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)

	presented, err := wallet.PresentMdocSelective(held, mdocSelectiveParams(), []dcql.Path{
		{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("given_name"), dcql.PathKey("extra")},
	})
	if err != nil {
		t.Fatalf("PresentMdocSelective: %v", err)
	}

	nameSpaces := decodePresentedMdocNameSpaces(t, presented)
	elements := nameSpaces["org.iso.18013.5.1"]
	if len(elements) != 2 {
		t.Errorf("org.iso.18013.5.1 elements = %v, want both given_name and family_name (fallback to full disclosure)", elements)
	}
}

// TestPresentCredentialsTrimsMdocToMatchedCredentialQuery drives the
// same trimming through the full PresentCredentials pipeline: a query
// asking only for given_name (testmdoc.Query's own shape), against a
// held credential that also carries family_name, must not disclose
// family_name in the resulting vp_token.
func TestPresentCredentialsTrimsMdocToMatchedCredentialQuery(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)

	vpToken, err := wallet.PresentCredentials(wallet.PresentationRequest{
		Query:                           testmdoc.Query(t),
		Credentials:                     []wallet.HeldCredential{held},
		Audience:                        "x509_hash:verifier",
		Nonce:                           "nonce-1",
		ResponseURI:                     "https://verifier.example.com/response",
		ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	if len(vpToken["mdl"]) != 1 {
		t.Fatalf("vp_token = %v", vpToken)
	}

	nameSpaces := decodePresentedMdocNameSpaces(t, vpToken["mdl"][0])
	elements := nameSpaces["org.iso.18013.5.1"]
	if len(elements) != 1 || elements[0] != "given_name" {
		t.Errorf("org.iso.18013.5.1 elements = %v, want exactly [given_name]", elements)
	}
}
