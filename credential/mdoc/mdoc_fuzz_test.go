package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// FuzzUnmarshalIssuerSigned exercises UnmarshalIssuerSigned/Verify
// against arbitrary CBOR bytes — an mdoc's own IssuerSigned structure
// (ISO/IEC 18013-5 §8.3.2.1.2.2) is presented by a Wallet inside an
// OID4VCI Credential Response or an OID4VP vp_token, attacker-supplied
// CBOR parsed and digest-checked before any of its claims are trusted.
// A value UnmarshalIssuerSigned accepts must also survive a Verify
// call without panicking, whether or not the signature/digests
// actually check out.
func FuzzUnmarshalIssuerSigned(f *testing.F) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate issuer key: %v", err)
	}
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate device key: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := selfSignedCert(f, &issuerKey.PublicKey, issuerKey)

	issuerSigned, err := Issue(issuerKey, cose.ES256, Claims{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string]map[string]interface{}{
			"org.iso.18013.5.1": {"given_name": "Alice", "family_name": "Doe"},
		},
		DeviceKey: &deviceKey.PublicKey,
		Signed:    now, ValidFrom: now, ValidUntil: now.Add(24 * time.Hour),
	}, IssueOptions{X5Chain: [][]byte{cert}})
	if err != nil {
		f.Fatalf("Issue: %v", err)
	}
	valid, err := issuerSigned.Marshal()
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}

	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add([]byte{0xa1})
	f.Add(valid[:len(valid)-1])

	f.Fuzz(func(t *testing.T, data []byte) {
		signed, err := UnmarshalIssuerSigned(data)
		if err != nil {
			return
		}
		_, _ = Verify(signed, "org.iso.18013.5.1.mDL", &issuerKey.PublicKey, cose.ES256, VerifyOptions{})
	})
}

// FuzzUnmarshalDeviceSigned exercises UnmarshalDeviceSigned/
// VerifyDeviceSignature against arbitrary CBOR bytes — mdoc's own
// DeviceSigned structure (§8.3.2.1.2.3), attacker-supplied inside the
// same OID4VP DeviceResponse.
func FuzzUnmarshalDeviceSigned(f *testing.F) {
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate device key: %v", err)
	}
	const docType = "org.iso.18013.5.1.mDL"
	sessionTranscriptBytes, err := wrapTag24([]interface{}{nil, nil, nil})
	if err != nil {
		f.Fatalf("wrapTag24(session transcript): %v", err)
	}

	valid, err := SignDeviceSignature(deviceKey, cose.ES256, sessionTranscriptBytes, docType, map[string]map[string]interface{}{})
	if err != nil {
		f.Fatalf("SignDeviceSignature: %v", err)
	}
	validBytes, err := valid.Marshal()
	if err != nil {
		f.Fatalf("Marshal: %v", err)
	}

	f.Add(validBytes)
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add(validBytes[:len(validBytes)-1])

	f.Fuzz(func(t *testing.T, data []byte) {
		signed, err := UnmarshalDeviceSigned(data)
		if err != nil {
			return
		}
		_ = VerifyDeviceSignature(signed, &deviceKey.PublicKey, cose.ES256, sessionTranscriptBytes, docType)
	})
}
