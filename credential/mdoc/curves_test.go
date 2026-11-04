package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// nistCurves are the curves an mdoc reader verifies with beyond P-256
// (ISO/IEC 18013-5 §9.1.2.4, §9.1.3.6, §9.1.5.2), with each one's COSE
// curve identifier, coordinate length and signature algorithm.
var nistCurves = []struct {
	curve elliptic.Curve
	crv   int64
	size  int
	alg   cose.Alg
}{
	{elliptic.P256(), 1, 32, cose.ES256},
	{elliptic.P384(), 2, 48, cose.ES384},
	{elliptic.P521(), 3, 66, cose.ES512},
}

func generate(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", curve.Params().Name, err)
	}
	return key
}

// A COSE_Key on P-384 or P-521 encodes with its own crv (2 or 3) and
// coordinates of its own length, round trips through CBOR, and decodes
// back to the same key.
func TestCoseKeyRoundTripNISTCurves(t *testing.T) {
	for _, tc := range nistCurves {
		key := generate(t, tc.curve)
		ck, err := NewCoseKey(&key.PublicKey)
		if err != nil {
			t.Fatalf("%s: NewCoseKey: %v", tc.curve.Params().Name, err)
		}
		if ck.Kty != coseKtyEC2 || ck.Crv != tc.crv || len(ck.X) != tc.size || len(ck.Y) != tc.size {
			t.Errorf("%s: kty %d crv %d, |x| %d |y| %d", tc.curve.Params().Name, ck.Kty, ck.Crv, len(ck.X), len(ck.Y))
		}
		wire, err := cbor.Marshal(ck)
		if err != nil {
			t.Fatal(err)
		}
		var back CoseKey
		if err := cbor.Unmarshal(wire, &back); err != nil {
			t.Fatal(err)
		}
		pub, err := back.PublicKey()
		if err != nil {
			t.Fatalf("%s: PublicKey: %v", tc.curve.Params().Name, err)
		}
		if ec, ok := pub.(*ecdsa.PublicKey); !ok || !ec.Equal(&key.PublicKey) {
			t.Errorf("%s: decoded a different key", tc.curve.Params().Name)
		}
	}
}

// A COSE_Key whose crv doesn't match its coordinates' length, or whose
// point isn't on its curve, or whose curve isn't supported, is refused.
func TestCoseKeyRefusesMismatchedCurve(t *testing.T) {
	p384, err := NewCoseKey(&generate(t, elliptic.P384()).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := NewCoseKey(&generate(t, elliptic.P256()).PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, k := range map[string]CoseKey{
		"P-384 coordinates marked P-256": {Kty: coseKtyEC2, Crv: coseCrvP256, X: p384.X, Y: p384.Y},
		"P-256 coordinates marked P-384": {Kty: coseKtyEC2, Crv: coseCrvP384, X: p256.X, Y: p256.Y},
		"P-384 coordinates marked P-521": {Kty: coseKtyEC2, Crv: coseCrvP521, X: append(make([]byte, 18), p384.X...), Y: append(make([]byte, 18), p384.Y...)},
		"brainpoolP256r1 (8)":            {Kty: coseKtyEC2, Crv: 8, X: p256.X, Y: p256.Y},
		"Ed448 (7)":                      {Kty: coseKtyOKP, Crv: 7, X: make([]byte, 57)},
	} {
		if _, err := k.PublicKey(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewCoseKey(&generate(t, elliptic.P224()).PublicKey); err == nil {
		t.Error("NewCoseKey accepted a P-224 key")
	}
}

// An mdoc whose document signer and device key are on P-384 or P-521 —
// and each combination with P-256 — issues, verifies, and has its
// device signature verified with the algorithm its keys' curves name.
func TestIssueVerifyNISTCurves(t *testing.T) {
	for _, issuer := range nistCurves {
		for _, device := range nistCurves {
			name := issuer.curve.Params().Name + " signer, " + device.curve.Params().Name + " device key"
			t.Run(name, func(t *testing.T) {
				issuerKey := generate(t, issuer.curve)
				deviceKey := generate(t, device.curve)
				claims := testClaims(t, &deviceKey.PublicKey)
				signed, err := Issue(issuerKey, issuer.alg, claims, IssueOptions{X5Chain: [][]byte{selfSignedCert(t, &issuerKey.PublicKey, issuerKey)}})
				if err != nil {
					t.Fatalf("Issue: %v", err)
				}
				opts := VerifyOptions{Now: func() time.Time { return claims.Signed.Add(time.Hour) }}
				verified, err := Verify(signed, claims.DocType, &issuerKey.PublicKey, issuer.alg, opts)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				for _, other := range nistCurves {
					if other.alg != issuer.alg {
						if _, err := Verify(signed, claims.DocType, &issuerKey.PublicKey, other.alg, opts); err == nil {
							t.Errorf("IssuerAuth verified as %d", other.alg)
						}
					}
				}
				if ec, ok := verified.DeviceKey.(*ecdsa.PublicKey); !ok || !ec.Equal(&deviceKey.PublicKey) {
					t.Fatalf("DeviceKey = %v", verified.DeviceKey)
				}
				alg, err := cose.AlgForKey(verified.DeviceKey)
				if err != nil || alg != device.alg {
					t.Fatalf("device key alg %d, %v", alg, err)
				}
				st := testSessionTranscriptBytes(t)
				ds, err := SignDeviceSignature(deviceKey, alg, st, claims.DocType, map[string]map[string]interface{}{})
				if err != nil {
					t.Fatalf("SignDeviceSignature: %v", err)
				}
				if err := VerifyDeviceSignature(ds, verified.DeviceKey, alg, st, claims.DocType); err != nil {
					t.Fatalf("VerifyDeviceSignature: %v", err)
				}
				other := generate(t, device.curve)
				if err := VerifyDeviceSignature(ds, &other.PublicKey, alg, st, claims.DocType); err == nil {
					t.Error("VerifyDeviceSignature accepted another key on the same curve")
				}
			})
		}
	}
}

// Issue refuses a signer whose curve isn't the algorithm's.
func TestIssueRefusesCurveAlgMismatch(t *testing.T) {
	p384 := generate(t, elliptic.P384())
	claims := testClaims(t, &generate(t, elliptic.P256()).PublicKey)
	for _, alg := range []cose.Alg{cose.ES256, cose.ES512} {
		if _, err := Issue(p384, alg, claims, IssueOptions{}); err == nil {
			t.Errorf("Issue signed with a P-384 key under %d", alg)
		}
	}
}

// DeviceMac works on P-384 and P-521 as on P-256 (§9.1.3.5): EMacKey
// from both sides' agreement, and from a key store's shared secret of
// the curve's length. Keys on two curves are refused.
func TestDeviceMACNISTCurves(t *testing.T) {
	st := testSessionTranscriptBytes(t)
	for _, tc := range nistCurves {
		device, reader := generate(t, tc.curve), generate(t, tc.curve)
		signed, err := ComputeDeviceMAC(device, &reader.PublicKey, st, testDeviceDocType, testDeviceNameSpaces())
		if err != nil {
			t.Fatalf("%s: ComputeDeviceMAC: %v", tc.curve.Params().Name, err)
		}
		if err := VerifyDeviceMAC(signed, &device.PublicKey, reader, st, testDeviceDocType); err != nil {
			t.Fatalf("%s: VerifyDeviceMAC: %v", tc.curve.Params().Name, err)
		}
		z := testSharedSecret(t, device, &reader.PublicKey)
		if len(z) != tc.size {
			t.Fatalf("%s: Z is %d bytes", tc.curve.Params().Name, len(z))
		}
		fromSecret, err := ComputeDeviceMACFromSharedSecret(z, st, testDeviceDocType, testDeviceNameSpaces())
		if err != nil {
			t.Fatalf("%s: ComputeDeviceMACFromSharedSecret: %v", tc.curve.Params().Name, err)
		}
		if err := VerifyDeviceMAC(fromSecret, &device.PublicKey, reader, st, testDeviceDocType); err != nil {
			t.Errorf("%s: shared-secret MAC: %v", tc.curve.Params().Name, err)
		}
	}
	p384, p521 := generate(t, elliptic.P384()), generate(t, elliptic.P521())
	if _, err := ComputeDeviceMAC(p384, &p521.PublicKey, st, testDeviceDocType, testDeviceNameSpaces()); err == nil {
		t.Error("ComputeDeviceMAC accepted a P-384 device key and a P-521 reader key")
	}
	p224a, p224b := generate(t, elliptic.P224()), generate(t, elliptic.P224())
	if _, err := ComputeDeviceMAC(p224a, &p224b.PublicKey, st, testDeviceDocType, testDeviceNameSpaces()); err == nil {
		t.Error("ComputeDeviceMAC accepted P-224 keys")
	}
}
