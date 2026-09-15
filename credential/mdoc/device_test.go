package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcigo/internal/cose"
)

const testDeviceDocType = "org.iso.18013.5.1.mDL"

func testSessionTranscriptBytes(t *testing.T) []byte {
	t.Helper()
	// SessionTranscript = [DeviceEngagementBytes/null,
	// EReaderKeyBytes/EncryptionParametersBytes/null, Handover]; all
	// three null (QRHandover = null) is structurally valid per §12.7.1's
	// own CDDL and is all this package's opaque treatment of
	// SessionTranscript needs for testing.
	b, err := wrapTag24([]interface{}{nil, nil, nil})
	if err != nil {
		t.Fatalf("build SessionTranscriptBytes: %v", err)
	}
	return b
}

func testDeviceNameSpaces() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		"org.iso.18013.5.1": {"age_over_21": true},
	}
}

func testP256KeyPair(t *testing.T) (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key, &key.PublicKey
}

// sigFixture is a freshly ES256-signed DeviceSigned (DeviceSignature
// form) plus the key behind it, shared by tests that just need "some
// validly signed DeviceSigned" rather than a specific scenario.
type sigFixture struct {
	key    *ecdsa.PrivateKey
	st     []byte
	signed DeviceSigned
}

func newSigFixture(t *testing.T) sigFixture {
	t.Helper()
	key, _ := testP256KeyPair(t)
	st := testSessionTranscriptBytes(t)
	signed, err := SignDeviceSignature(key, cose.ES256, st, testDeviceDocType, testDeviceNameSpaces())
	if err != nil {
		t.Fatalf("SignDeviceSignature: %v", err)
	}
	return sigFixture{key: key, st: st, signed: signed}
}

// macFixture is a freshly computed DeviceSigned (DeviceMac form) plus
// the device/reader keys behind it.
type macFixture struct {
	devicePriv *ecdsa.PrivateKey
	devicePub  *ecdsa.PublicKey
	readerPriv *ecdsa.PrivateKey
	readerPub  *ecdsa.PublicKey
	st         []byte
	signed     DeviceSigned
}

func newMACFixture(t *testing.T) macFixture {
	t.Helper()
	devicePriv, devicePub := testP256KeyPair(t)
	readerPriv, readerPub := testP256KeyPair(t)
	st := testSessionTranscriptBytes(t)
	signed, err := ComputeDeviceMAC(devicePriv, readerPub, st, testDeviceDocType, testDeviceNameSpaces())
	if err != nil {
		t.Fatalf("ComputeDeviceMAC: %v", err)
	}
	return macFixture{
		devicePriv: devicePriv, devicePub: devicePub,
		readerPriv: readerPriv, readerPub: readerPub,
		st: st, signed: signed,
	}
}

func TestSignVerifyDeviceSignatureES256(t *testing.T) {
	f := newSigFixture(t)
	if f.signed.AuthType != DeviceAuthSignature {
		t.Errorf("AuthType = %d, want DeviceAuthSignature", f.signed.AuthType)
	}
	if err := VerifyDeviceSignature(f.signed, &f.key.PublicKey, cose.ES256, f.st, testDeviceDocType); err != nil {
		t.Fatalf("VerifyDeviceSignature: %v", err)
	}
}

func TestSignVerifyDeviceSignatureEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	st := testSessionTranscriptBytes(t)
	signed, err := SignDeviceSignature(priv, cose.EdDSA, st, testDeviceDocType, testDeviceNameSpaces())
	if err != nil {
		t.Fatalf("SignDeviceSignature: %v", err)
	}
	if err := VerifyDeviceSignature(signed, pub, cose.EdDSA, st, testDeviceDocType); err != nil {
		t.Fatalf("VerifyDeviceSignature: %v", err)
	}
}

func TestVerifyDeviceSignatureRejectsWrongKey(t *testing.T) {
	f := newSigFixture(t)
	_, otherPub := testP256KeyPair(t)
	if err := VerifyDeviceSignature(f.signed, otherPub, cose.ES256, f.st, testDeviceDocType); err == nil {
		t.Errorf("VerifyDeviceSignature accepted the wrong key")
	}
}

func TestVerifyDeviceSignatureRejectsWrongDocType(t *testing.T) {
	f := newSigFixture(t)
	if err := VerifyDeviceSignature(f.signed, &f.key.PublicKey, cose.ES256, f.st, "org.iso.other.docType"); err == nil {
		t.Errorf("VerifyDeviceSignature accepted the wrong docType")
	}
}

func TestVerifyDeviceSignatureRejectsWrongSessionTranscript(t *testing.T) {
	f := newSigFixture(t)
	otherST, err := wrapTag24([]interface{}{nil, nil, "not-null"})
	if err != nil {
		t.Fatalf("build other SessionTranscriptBytes: %v", err)
	}
	if err := VerifyDeviceSignature(f.signed, &f.key.PublicKey, cose.ES256, otherST, testDeviceDocType); err == nil {
		t.Errorf("VerifyDeviceSignature accepted the wrong SessionTranscriptBytes")
	}
}

// TestVerifyDeviceSignatureRejectsTamperedNameSpaces simulates real
// wire tampering — swapping in different nameSpacesBytes, the way
// UnmarshalDeviceSigned would if the wire bytes it decoded had been
// altered — rather than mutating the decoded NameSpaces map directly
// (which the cached nameSpacesBytes wouldn't reflect).
func TestVerifyDeviceSignatureRejectsTamperedNameSpaces(t *testing.T) {
	f := newSigFixture(t)
	tampered, err := wrapTag24(map[string]map[string]interface{}{
		"org.iso.18013.5.1": {"age_over_21": false},
	})
	if err != nil {
		t.Fatalf("build tampered nameSpacesBytes: %v", err)
	}
	f.signed.nameSpacesBytes = tampered

	if err := VerifyDeviceSignature(f.signed, &f.key.PublicKey, cose.ES256, f.st, testDeviceDocType); err == nil {
		t.Errorf("VerifyDeviceSignature accepted tampered nameSpaces")
	}
}

func TestSignDeviceSignatureRejectsMalformedSessionTranscriptBytes(t *testing.T) {
	key, _ := testP256KeyPair(t)
	if _, err := SignDeviceSignature(key, cose.ES256, []byte("not cbor"), testDeviceDocType, testDeviceNameSpaces()); err == nil {
		t.Errorf("SignDeviceSignature accepted malformed SessionTranscriptBytes")
	}
}

func TestComputeVerifyDeviceMAC(t *testing.T) {
	f := newMACFixture(t)
	if f.signed.AuthType != DeviceAuthMAC {
		t.Errorf("AuthType = %d, want DeviceAuthMAC", f.signed.AuthType)
	}
	if err := VerifyDeviceMAC(f.signed, f.devicePub, f.readerPriv, f.st, testDeviceDocType); err != nil {
		t.Fatalf("VerifyDeviceMAC: %v", err)
	}
}

func TestVerifyDeviceMACRejectsWrongReaderKey(t *testing.T) {
	f := newMACFixture(t)
	otherReaderPriv, _ := testP256KeyPair(t)
	if err := VerifyDeviceMAC(f.signed, f.devicePub, otherReaderPriv, f.st, testDeviceDocType); err == nil {
		t.Errorf("VerifyDeviceMAC accepted the wrong reader key")
	}
}

func TestVerifyDeviceMACRejectsWrongDeviceKey(t *testing.T) {
	f := newMACFixture(t)
	_, otherDevicePub := testP256KeyPair(t)
	if err := VerifyDeviceMAC(f.signed, otherDevicePub, f.readerPriv, f.st, testDeviceDocType); err == nil {
		t.Errorf("VerifyDeviceMAC accepted the wrong device key")
	}
}

func TestDeriveEMacKeyRejectsNonP256(t *testing.T) {
	p384Priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	_, p256Pub := testP256KeyPair(t)
	if _, err := deriveEMacKey(p384Priv, p256Pub, []byte("st")); err == nil {
		t.Errorf("deriveEMacKey accepted a non-P-256 private key")
	}

	p256Priv, _ := testP256KeyPair(t)
	p384Pub, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := deriveEMacKey(p256Priv, &p384Pub.PublicKey, []byte("st")); err == nil {
		t.Errorf("deriveEMacKey accepted a non-P-256 public key")
	}
}

func TestDeviceSignedMarshalUnmarshalRoundTrip(t *testing.T) {
	f := newSigFixture(t)
	wire, err := f.signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := UnmarshalDeviceSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalDeviceSigned: %v", err)
	}
	if decoded.AuthType != DeviceAuthSignature {
		t.Errorf("decoded.AuthType = %d, want DeviceAuthSignature", decoded.AuthType)
	}
	if err := VerifyDeviceSignature(decoded, &f.key.PublicKey, cose.ES256, f.st, testDeviceDocType); err != nil {
		t.Fatalf("VerifyDeviceSignature(decoded): %v", err)
	}
	if got, ok := decoded.NameSpaces["org.iso.18013.5.1"]["age_over_21"].(bool); !ok || !got {
		t.Errorf("age_over_21 = %v, want true", decoded.NameSpaces["org.iso.18013.5.1"]["age_over_21"])
	}
}

func TestDeviceSignedMACMarshalUnmarshalRoundTrip(t *testing.T) {
	f := newMACFixture(t)
	wire, err := f.signed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := UnmarshalDeviceSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalDeviceSigned: %v", err)
	}
	if decoded.AuthType != DeviceAuthMAC {
		t.Errorf("decoded.AuthType = %d, want DeviceAuthMAC", decoded.AuthType)
	}
	if err := VerifyDeviceMAC(decoded, f.devicePub, f.readerPriv, f.st, testDeviceDocType); err != nil {
		t.Fatalf("VerifyDeviceMAC(decoded): %v", err)
	}
}

func TestUnmarshalDeviceSignedRejectsMalformedInput(t *testing.T) {
	if _, err := UnmarshalDeviceSigned([]byte("not cbor")); err == nil {
		t.Errorf("UnmarshalDeviceSigned accepted malformed input")
	}
}

func TestDeviceSignedMarshalRejectsUnknownAuthType(t *testing.T) {
	signed := DeviceSigned{NameSpaces: testDeviceNameSpaces(), DeviceAuth: []byte{0x80}, AuthType: 0}
	if _, err := signed.Marshal(); err == nil {
		t.Errorf("Marshal accepted an unset AuthType")
	}
}

func TestCheckKeyAuthorizations(t *testing.T) {
	nameSpaces := map[string]map[string]interface{}{
		"org.iso.18013.5.1": {"age_over_21": true, "portrait": []byte("x")},
	}

	t.Run("whole namespace authorized", func(t *testing.T) {
		auth := &KeyAuthorizations{NameSpaces: []string{"org.iso.18013.5.1"}}
		if err := CheckKeyAuthorizations(nameSpaces, auth); err != nil {
			t.Errorf("CheckKeyAuthorizations: %v", err)
		}
	})

	t.Run("specific elements authorized", func(t *testing.T) {
		auth := &KeyAuthorizations{DataElements: map[string][]string{
			"org.iso.18013.5.1": {"age_over_21", "portrait"},
		}}
		if err := CheckKeyAuthorizations(nameSpaces, auth); err != nil {
			t.Errorf("CheckKeyAuthorizations: %v", err)
		}
	})

	t.Run("missing element rejected", func(t *testing.T) {
		auth := &KeyAuthorizations{DataElements: map[string][]string{
			"org.iso.18013.5.1": {"age_over_21"},
		}}
		if err := CheckKeyAuthorizations(nameSpaces, auth); err == nil {
			t.Errorf("CheckKeyAuthorizations accepted an unauthorized element")
		}
	})

	t.Run("unauthorized namespace rejected", func(t *testing.T) {
		auth := &KeyAuthorizations{NameSpaces: []string{"org.iso.18013.5.1.aamva"}}
		if err := CheckKeyAuthorizations(nameSpaces, auth); err == nil {
			t.Errorf("CheckKeyAuthorizations accepted an unauthorized namespace")
		}
	})

	t.Run("nil auth rejects non-empty nameSpaces", func(t *testing.T) {
		if err := CheckKeyAuthorizations(nameSpaces, nil); err == nil {
			t.Errorf("CheckKeyAuthorizations accepted nil auth with non-empty nameSpaces")
		}
	})

	t.Run("nil auth accepts empty nameSpaces", func(t *testing.T) {
		if err := CheckKeyAuthorizations(map[string]map[string]interface{}{}, nil); err != nil {
			t.Errorf("CheckKeyAuthorizations rejected empty nameSpaces with nil auth: %v", err)
		}
	})
}

// TestDeviceSignedMapValuedElementVerifiesReliably is DeviceSigned's
// counterpart to TestMapValuedElementValueVerifiesReliably: a
// map-valued DeviceSignedItems value must verify reliably across
// repeated Sign/Marshal/Unmarshal/Verify cycles, since Go's map
// iteration order is randomized per range.
func TestDeviceSignedMapValuedElementVerifiesReliably(t *testing.T) {
	key, _ := testP256KeyPair(t)
	st := testSessionTranscriptBytes(t)
	nameSpaces := map[string]map[string]interface{}{
		"org.iso.18013.5.1": {
			"nested": map[string]interface{}{
				"alpha": 1, "bravo": 2, "charlie": 3, "delta": 4,
				"echo": 5, "foxtrot": 6, "golf": 7, "hotel": 8,
			},
		},
	}

	for i := 0; i < 20; i++ {
		signed, err := SignDeviceSignature(key, cose.ES256, st, testDeviceDocType, nameSpaces)
		if err != nil {
			t.Fatalf("iteration %d: SignDeviceSignature: %v", i, err)
		}
		if err := VerifyDeviceSignature(signed, &key.PublicKey, cose.ES256, st, testDeviceDocType); err != nil {
			t.Fatalf("iteration %d: VerifyDeviceSignature (in-memory): %v", i, err)
		}

		wire, err := signed.Marshal()
		if err != nil {
			t.Fatalf("iteration %d: Marshal: %v", i, err)
		}
		decoded, err := UnmarshalDeviceSigned(wire)
		if err != nil {
			t.Fatalf("iteration %d: UnmarshalDeviceSigned: %v", i, err)
		}
		if err := VerifyDeviceSignature(decoded, &key.PublicKey, cose.ES256, st, testDeviceDocType); err != nil {
			t.Fatalf("iteration %d: VerifyDeviceSignature (wire round trip): %v", i, err)
		}
	}
}
