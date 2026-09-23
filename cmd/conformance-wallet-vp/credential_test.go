package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// TestIssueFixtureCredential_SetsExp reuses setupWalletUnderTest (the
// same real issueFixtureCredential call path integration_test.go's
// own full round-trip test exercises) rather than duplicating its own
// key/CA/cert setup, and just checks the one thing that test doesn't:
// the issued credential's own "exp" claim, day-rounded per
// sdjwtvc.RoundedExp's own doc comment.
func TestIssueFixtureCredential_SetsExp(t *testing.T) {
	before := time.Now()
	wallet, _ := setupWalletUnderTest(t)

	issuerJWT, _, _ := strings.Cut(wallet.cred.Credential, "~")
	_, rawPayload, err := jose.DecodeUnverified(issuerJWT)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	var payload struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Exp == nil {
		t.Fatal("issued credential has no exp claim")
	}
	want := sdjwtvc.RoundedExp(before, fixtureCredentialLifetime)
	if *payload.Exp != want {
		t.Errorf("exp = %d, want %d (day-rounded issuance + fixtureCredentialLifetime)", *payload.Exp, want)
	}
}

// mdocFixtureIssuerConfig generates a throwaway ISO/IEC 18013-5 IACA +
// Document Signer identity and returns the Config fields
// issueFixtureMdocCredential needs, mirroring
// conformance/wallet-vp/scripts/run-modules's own generateWalletVPFixtures.
func mdocFixtureIssuerConfig(t *testing.T) Config {
	t.Helper()
	iacaCert, iacaKey, _, _, err := conformancecert.GenerateMdocIACA("test-mdoc-iaca", "FR", "https://example.com/contact")
	if err != nil {
		t.Fatalf("GenerateMdocIACA: %v", err)
	}
	_, dsKeyPEM, dsCertPEM, err := conformancecert.GenerateMdocDocumentSigner("test-mdoc-ds", "FR", "https://example.com/contact", "https://example.com/crl", iacaCert, iacaKey)
	if err != nil {
		t.Fatalf("GenerateMdocDocumentSigner: %v", err)
	}
	return Config{
		MdocIssuerPrivateKeyPEM:  dsKeyPEM,
		MdocIssuerCertificatePEM: dsCertPEM,
		MdocDocType:              "org.iso.18013.5.1.mDL",
		MdocNamespace:            "org.iso.18013.5.1",
	}
}

// TestIssueFixtureMdocCredential_AllMandatoryClaimTypes proves
// issueFixtureMdocCredential/conformanceconfig.BuildMdocNameSpaceElements
// handle every ISO/IEC 18013-5 Table 20 value shape a real "M"
// (mandatory) org.iso.18013.5.1.mDL data element needs — plain tstr,
// full-date-tagged dates (birth_date/issue_date/expiry_date), a
// base64-encoded portrait, and driving_privileges' own nested
// array-of-maps — not just the two plain-string claims
// (given_name/family_name) TestIssueFixtureCredential_SetsExp's own
// "dc+sd-jwt" counterpart exercises. Found live against the real
// hosted OIDF conformance suite: oid4vp-1final-wallet-all-mandatory-claims
// queries every mandatory element via its own built-in DCQL query,
// which a two-claim fixture fails with "no held credential satisfies
// this credential query".
func TestIssueFixtureMdocCredential_AllMandatoryClaimTypes(t *testing.T) {
	cfg := mdocFixtureIssuerConfig(t)
	cfg.MdocClaims = map[string]any{
		"given_name":             "Jean",
		"family_name":            "Dupont",
		"birth_date":             "1990-01-01",
		"issue_date":             "2024-01-01",
		"expiry_date":            "2034-01-01",
		"issuing_country":        "FR",
		"issuing_authority":      "Conformance Test Authority",
		"document_number":        "123456789",
		"portrait":               base64.StdEncoding.EncodeToString([]byte("jpeg-bytes")),
		"un_distinguishing_sign": "F",
		"driving_privileges": []any{
			map[string]any{"vehicle_category_code": "B"},
		},
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}

	held, err := issueFixtureMdocCredential(cfg, deviceKey)
	if err != nil {
		t.Fatalf("issueFixtureMdocCredential: %v", err)
	}
	if held.Format != mdoc.CredentialFormat {
		t.Errorf("Format = %q, want %q", held.Format, mdoc.CredentialFormat)
	}

	wire, err := base64.RawURLEncoding.DecodeString(held.Credential)
	if err != nil {
		t.Fatalf("decode held.Credential: %v", err)
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}
	got := map[string]bool{}
	for _, item := range issuerSigned.NameSpaces[cfg.MdocNamespace] {
		got[item.ElementIdentifier] = true
	}
	for name := range cfg.MdocClaims {
		if !got[name] {
			t.Errorf("issued mdoc is missing data element %q", name)
		}
	}
}

// TestIssueFixtureMdocCredential_RejectsBadClaimShape proves a
// malformed claim (here, a non-string birth_date) surfaces as an
// issueFixtureMdocCredential error rather than panicking or silently
// mis-encoding — conformanceconfig.BuildMdocNameSpaceElements' own
// error path, now reachable through this function since it stopped
// building nameSpaceClaims by hand.
func TestIssueFixtureMdocCredential_RejectsBadClaimShape(t *testing.T) {
	cfg := mdocFixtureIssuerConfig(t)
	cfg.MdocClaims = map[string]any{"birth_date": 19900101}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}

	if _, err := issueFixtureMdocCredential(cfg, deviceKey); err == nil {
		t.Fatal("issueFixtureMdocCredential = nil error, want error for a non-string birth_date claim")
	}
}
