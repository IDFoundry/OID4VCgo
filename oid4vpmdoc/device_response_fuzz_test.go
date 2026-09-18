package oid4vpmdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// FuzzUnmarshalDeviceResponse exercises UnmarshalDeviceResponse against
// arbitrary CBOR bytes — the top-level structure an OID4VP mdoc
// vp_token wraps, entirely attacker-supplied and parsed (including
// nested IssuerSigned/DeviceSigned decoding) before any signature is
// checked.
func FuzzUnmarshalDeviceResponse(f *testing.F) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate issuer key: %v", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate device key: %v", err)
	}
	const docType = "org.iso.18013.5.1.mDL"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	issuerSigned, err := mdoc.Issue(issuerKey, cose.ES256, mdoc.Claims{
		DocType: docType,
		NameSpaces: map[string]map[string]interface{}{
			"org.iso.18013.5.1": {"given_name": "Alice"},
		},
		DeviceKey: &deviceKey.PublicKey,
		Signed:    now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{[]byte("fuzz-cert")}})
	if err != nil {
		f.Fatalf("mdoc.Issue: %v", err)
	}
	sessionTranscriptBytes, err := BuildSessionTranscriptBytes(HandoverParams{
		ClientID: "https://verifier.example", Nonce: "fuzz-nonce",
		ResponseURI:                     "https://verifier.example/response",
		ResponseEncryptionJWKThumbprint: []byte("fuzz-thumbprint-32-bytes-long!!"),
	})
	if err != nil {
		f.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(deviceKey, cose.ES256, sessionTranscriptBytes, docType, map[string]map[string]interface{}{})
	if err != nil {
		f.Fatalf("mdoc.SignDeviceSignature: %v", err)
	}
	valid, err := MarshalDeviceResponse(Document{DocType: docType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned})
	if err != nil {
		f.Fatalf("MarshalDeviceResponse: %v", err)
	}

	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add(valid[:len(valid)-1])

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalDeviceResponse(data)
	})
}
