package wallet_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/testcert"
	"github.com/idfoundry/oid4vcigo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcigo/wallet"
)

const testMdocDocType = "org.iso.18013.5.1.mDL"

// heldMdocFixture is a real, freshly issued "mso_mdoc" credential
// wrapped as a wallet.HeldCredential — the setup every
// MatchDCQLQuery/PresentMdoc test for this format needs.
type heldMdocFixture struct {
	issuerKey *ecdsa.PrivateKey
	deviceKey *ecdsa.PrivateKey
	held      wallet.HeldCredential
}

func newHeldMdoc(t *testing.T) heldMdocFixture {
	t.Helper()
	issuerKey := testP256Key(t)
	deviceKey := testP256Key(t)
	cert := testcert.SelfSigned(t, "wallet mdoc test issuer", &issuerKey.PublicKey, issuerKey)

	signed := time.Now()
	issuerSigned, err := mdoc.Issue(issuerKey, cose.ES256, mdoc.Claims{
		DocType: testMdocDocType,
		NameSpaces: map[string]map[string]interface{}{
			"org.iso.18013.5.1": {"given_name": "Alice", "family_name": "Doe"},
		},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed,
		ValidFrom:  signed,
		ValidUntil: signed.Add(24 * time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{cert.Raw}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}
	encoded, err := issuerSigned.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return heldMdocFixture{
		issuerKey: issuerKey, deviceKey: deviceKey,
		held: wallet.HeldCredential{
			Format: mdoc.CredentialFormat, Credential: base64.RawURLEncoding.EncodeToString(encoded),
			HolderKey: deviceKey, MdocDocType: testMdocDocType,
		},
	}
}

func testMdocPresentationQuery(t *testing.T) dcql.Query {
	t.Helper()
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: testMdocDocType})
	if err != nil {
		t.Fatalf("NewMdocMeta: %v", err)
	}
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "mdl", Format: mdoc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("given_name")}}},
	}}}
}

func TestMatchDCQLQueryMdoc(t *testing.T) {
	fixture := newHeldMdoc(t)
	matches, err := wallet.MatchDCQLQuery(testMdocPresentationQuery(t), []wallet.HeldCredential{fixture.held})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches) != 1 || matches["mdl"].Credential != fixture.held.Credential {
		t.Errorf("matches = %+v", matches)
	}
}

func TestMatchDCQLQueryMdocRejectsWrongDoctype(t *testing.T) {
	fixture := newHeldMdoc(t)
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: "org.iso.18013.5.1.mVRC"})
	if err != nil {
		t.Fatalf("NewMdocMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "x", Format: mdoc.CredentialFormat, Meta: meta}}}
	if _, err := wallet.MatchDCQLQuery(query, []wallet.HeldCredential{fixture.held}); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

func TestPresentMdoc(t *testing.T) {
	fixture := newHeldMdoc(t)
	presented, err := wallet.PresentMdoc(fixture.held, wallet.PresentMdocParams{
		Audience: "x509_hash:verifier", Nonce: "nonce-1",
		ResponseURI: "https://verifier.example.com/response", ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("PresentMdoc: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		t.Fatalf("UnmarshalDeviceResponse: %v", err)
	}
	if doc.DocType != testMdocDocType {
		t.Errorf("DocType = %q, want %q", doc.DocType, testMdocDocType)
	}

	sessionTranscriptBytes, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: "x509_hash:verifier", Nonce: "nonce-1",
		ResponseURI: "https://verifier.example.com/response", ResponseEncryptionJWKThumbprint: make([]byte, 32),
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, &fixture.deviceKey.PublicKey, cose.ES256, sessionTranscriptBytes, testMdocDocType); err != nil {
		t.Fatalf("VerifyDeviceSignature: %v", err)
	}

	verified, err := mdoc.Verify(doc.IssuerSigned, &fixture.issuerKey.PublicKey, cose.ES256, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["given_name"]; got != "Alice" {
		t.Errorf("given_name = %v, want Alice", got)
	}
}

func TestPresentMdocRejectsWrongFormat(t *testing.T) {
	held := wallet.HeldCredential{Format: "dc+sd-jwt", Credential: "irrelevant"}
	if _, err := wallet.PresentMdoc(held, wallet.PresentMdocParams{}); err == nil {
		t.Fatalf("PresentMdoc = nil error, want error")
	}
}

func TestPresentMdocRejectsMissingDocType(t *testing.T) {
	fixture := newHeldMdoc(t)
	held := fixture.held
	held.MdocDocType = ""
	if _, err := wallet.PresentMdoc(held, wallet.PresentMdocParams{
		Audience: "aud", Nonce: "nonce", ResponseURI: "https://verifier.example.com/response",
	}); err == nil {
		t.Fatalf("PresentMdoc = nil error, want error")
	}
}
