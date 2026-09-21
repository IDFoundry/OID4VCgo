package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// heldMdoc wraps a real, freshly issued testmdoc.Fixture as a
// wallet.HeldCredential — the setup every MatchDCQLQuery/PresentMdoc
// test for this format needs.
func heldMdoc(t *testing.T, f testmdoc.Fixture) wallet.HeldCredential {
	t.Helper()
	encoded, err := f.IssuerSigned.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return wallet.HeldCredential{
		Format: mdoc.CredentialFormat, Credential: base64.RawURLEncoding.EncodeToString(encoded),
		HolderKey: f.DeviceKey, MdocDocType: testmdoc.DocType,
	}
}

func TestMatchDCQLQueryMdoc(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)
	matches, err := wallet.MatchDCQLQuery(context.Background(), testmdoc.Query(t), []wallet.HeldCredential{held}, nil)
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches["mdl"]) != 1 || matches["mdl"][0].Credential != held.Credential {
		t.Errorf("matches = %+v", matches)
	}
}

func TestMatchDCQLQueryMdocRejectsWrongDoctype(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: "org.iso.18013.5.1.mVRC"})
	if err != nil {
		t.Fatalf("NewMdocMeta: %v", err)
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "x", Format: mdoc.CredentialFormat, Meta: meta}}}
	if _, err := wallet.MatchDCQLQuery(context.Background(), query, []wallet.HeldCredential{held}, nil); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error")
	}
}

// assertPresentedMdoc decodes presented (a wallet.PresentMdoc result),
// checks its own DocType, verifies DeviceSigned against
// wantSessionTranscriptBytes (whichever flow's own Handover the
// caller built it with) and f's own DeviceKey, and checks IssuerSigned
// verifies with given_name "Alice" — the shared tail
// TestPresentMdoc/TestPresentMdocDCAPI both need, differing only in
// which flow's own SessionTranscriptBytes they expect DeviceSigned to
// have been computed over.
func assertPresentedMdoc(t *testing.T, presented string, f testmdoc.Fixture, wantSessionTranscriptBytes []byte) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(presented)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	doc, err := oid4vpmdoc.UnmarshalDeviceResponse(raw)
	if err != nil {
		t.Fatalf("UnmarshalDeviceResponse: %v", err)
	}
	if doc.DocType != testmdoc.DocType {
		t.Errorf("DocType = %q, want %q", doc.DocType, testmdoc.DocType)
	}

	if err := mdoc.VerifyDeviceSignature(doc.DeviceSigned, &f.DeviceKey.PublicKey, cose.ES256, wantSessionTranscriptBytes, testmdoc.DocType); err != nil {
		t.Fatalf("VerifyDeviceSignature: %v", err)
	}

	verified, err := mdoc.Verify(doc.IssuerSigned, testmdoc.DocType, &f.IssuerKey.PublicKey, cose.ES256, mdoc.VerifyOptions{})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if got := verified.NameSpaces["org.iso.18013.5.1"]["given_name"]; got != "Alice" {
		t.Errorf("given_name = %v, want Alice", got)
	}
}

func TestPresentMdoc(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate response encryption key: %v", err)
	}
	presented, err := wallet.PresentMdoc(held, wallet.PresentMdocParams{
		Audience: "x509_hash:verifier", Nonce: "nonce-1",
		ResponseURI: "https://verifier.example.com/response", ResponseEncryptionKey: &encKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("PresentMdoc: %v", err)
	}

	sessionTranscriptBytes, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: "x509_hash:verifier", Nonce: "nonce-1",
		ResponseURI: "https://verifier.example.com/response", ResponseEncryptionJWKThumbprint: testmdoc.ResponseEncryptionThumbprint(t, encKey),
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	assertPresentedMdoc(t, presented, f, sessionTranscriptBytes)
}

// TestPresentMdocDCAPI mirrors TestPresentMdoc for the DC API flow:
// PresentMdocParams.Origin set builds DeviceSigned over the DC API
// flow's own OpenID4VPDCAPIHandover (Appendix B.2.6.2) instead.
func TestPresentMdocDCAPI(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate response encryption key: %v", err)
	}
	presented, err := wallet.PresentMdoc(held, wallet.PresentMdocParams{
		Origin: "https://verifier.example.com", Nonce: "nonce-1", ResponseEncryptionKey: &encKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("PresentMdoc: %v", err)
	}

	sessionTranscriptBytes, err := oid4vpmdoc.BuildDCAPISessionTranscriptBytes(oid4vpmdoc.DCAPIHandoverParams{
		Origin: "https://verifier.example.com", Nonce: "nonce-1", ResponseEncryptionJWKThumbprint: testmdoc.ResponseEncryptionThumbprint(t, encKey),
	})
	if err != nil {
		t.Fatalf("BuildDCAPISessionTranscriptBytes: %v", err)
	}
	assertPresentedMdoc(t, presented, f, sessionTranscriptBytes)
}

func TestPresentMdocRejectsWrongFormat(t *testing.T) {
	held := wallet.HeldCredential{Format: "dc+sd-jwt", Credential: "irrelevant"}
	if _, err := wallet.PresentMdoc(held, wallet.PresentMdocParams{}); err == nil {
		t.Fatalf("PresentMdoc = nil error, want error")
	}
}

func TestPresentMdocRejectsMissingDocType(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)
	held.MdocDocType = ""
	if _, err := wallet.PresentMdoc(held, wallet.PresentMdocParams{
		Audience: "aud", Nonce: "nonce", ResponseURI: "https://verifier.example.com/response",
	}); err == nil {
		t.Fatalf("PresentMdoc = nil error, want error")
	}
}
