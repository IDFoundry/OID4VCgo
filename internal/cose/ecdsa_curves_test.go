package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

// curveCases are the ECDSA algorithms with their curve and the octet
// length of each of r and s (RFC 9053 §2.1).
var curveCases = []struct {
	alg   Alg
	esp   Alg
	curve elliptic.Curve
	size  int
}{
	{ES256, esp256, elliptic.P256(), 32},
	{ES384, esp384, elliptic.P384(), 48},
	{ES512, esp512, elliptic.P521(), 66},
}

// signWithHeaderAlg signs payload under alg with key, but writes
// headerAlg into the protected header: a signature marked as another
// algorithm than it was made with.
func signWithHeaderAlg(t *testing.T, alg, headerAlg Alg, key crypto.Signer, payload []byte) []byte {
	t.Helper()
	protected, err := encMode.Marshal(map[int]interface{}{labelAlg: int64(headerAlg)})
	if err != nil {
		t.Fatal(err)
	}
	toSign, err := encMode.Marshal(sigStructure{Context: "Signature1", BodyProtected: protected, ExternalAAD: []byte{}, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signBytes(alg, key, toSign)
	if err != nil {
		t.Fatal(err)
	}
	sign1, err := encMode.Marshal(rawSign1{Protected: protected, Unprotected: map[int]interface{}{}, Payload: payload, Signature: sig})
	if err != nil {
		t.Fatal(err)
	}
	return sign1
}

// Each ECDSA algorithm signs and verifies on its own curve, embedded,
// detached and tagged, and with a fixed-width signature of twice its
// curve's octet length.
func TestSignVerifyECDSACurves(t *testing.T) {
	for _, tc := range curveCases {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			sign1, err := Sign(tc.alg, key, Headers{}, Headers{}, []byte("payload"), []byte("aad"))
			if err != nil {
				t.Fatal(err)
			}
			protected, _, payload, err := Verify(tc.alg, &key.PublicKey, sign1, []byte("aad"))
			if err != nil || protected.Alg != tc.alg || string(payload) != "payload" {
				t.Fatalf("Verify: %v, %d, %q", err, protected.Alg, payload)
			}
			raw, err := decodeRaw(sign1, MaxBytes)
			if err != nil || len(raw.Signature) != 2*tc.size {
				t.Errorf("signature is %d bytes, want %d (%v)", len(raw.Signature), 2*tc.size, err)
			}
			detached, err := SignDetached(tc.alg, key, Headers{}, Headers{}, []byte("detached"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := VerifyDetached(tc.alg, &key.PublicKey, detached, []byte("detached"), nil); err != nil {
				t.Errorf("VerifyDetached: %v", err)
			}
			tagged, err := SignTagged(tc.alg, key, Headers{}, Headers{}, []byte("payload"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := VerifyTagged(tc.alg, &key.PublicKey, tagged, nil); err != nil {
				t.Errorf("VerifyTagged: %v", err)
			}
			if _, _, _, err := Verify(tc.alg, &key.PublicKey, sign1, []byte("other aad")); err == nil {
				t.Error("verified under the wrong external AAD")
			}
		})
	}
}

// An algorithm is used with its own curve only: signing or verifying
// with a key on any other curve, or an Ed25519 key, is refused.
func TestECDSACurveMustMatchAlg(t *testing.T) {
	keys := map[string]*ecdsa.PrivateKey{}
	for _, tc := range curveCases {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[tc.curve.Params().Name] = key
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range curveCases {
		own := keys[tc.curve.Params().Name]
		sign1, err := Sign(tc.alg, own, Headers{}, Headers{}, []byte("payload"), nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, other := range keys {
			if other == own {
				continue
			}
			if _, err := Sign(tc.alg, other, Headers{}, Headers{}, []byte("payload"), nil); err == nil {
				t.Errorf("alg %d signed with a %s key", tc.alg, name)
			}
			if _, _, _, err := Verify(tc.alg, &other.PublicKey, sign1, nil); err == nil || !strings.Contains(err.Error(), "requires a "+tc.curve.Params().Name) {
				t.Errorf("alg %d verified with a %s key: %v", tc.alg, name, err)
			}
		}
		if _, err := Sign(tc.alg, edKey, Headers{}, Headers{}, []byte("payload"), nil); err == nil {
			t.Errorf("alg %d signed with an Ed25519 key", tc.alg)
		}
		if _, _, _, err := Verify(tc.alg, edKey.Public(), sign1, nil); err == nil {
			t.Errorf("alg %d verified with an Ed25519 key", tc.alg)
		}
	}
}

// The protected header's alg must name the algorithm verified with —
// itself or its ESP alias (RFC 9864) — and never another curve's: a
// P-384 key's ES384 signature marked ES256 or ES512, or another
// curve's ESP alias, is refused.
func TestVerifyHeaderAlgPerCurve(t *testing.T) {
	for _, tc := range curveCases {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := Verify(tc.alg, &key.PublicKey, signWithHeaderAlg(t, tc.alg, tc.esp, key, []byte("p")), nil); err != nil {
			t.Errorf("alg %d marked %d: %v", tc.alg, tc.esp, err)
		}
		for _, other := range curveCases {
			if other.alg == tc.alg {
				continue
			}
			for _, header := range []Alg{other.alg, other.esp} {
				if _, _, _, err := Verify(tc.alg, &key.PublicKey, signWithHeaderAlg(t, tc.alg, header, key, []byte("p")), nil); err == nil {
					t.Errorf("alg %d marked %d verified", tc.alg, header)
				}
			}
		}
		if _, _, _, err := Verify(tc.alg, &key.PublicKey, signWithHeaderAlg(t, tc.alg, EdDSA, key, []byte("p")), nil); err == nil {
			t.Errorf("alg %d marked EdDSA verified", tc.alg)
		}
	}
}

// A signature of any length but twice the curve's octet length — a
// shorter curve's, a longer one's, one octet off, or DER — is refused
// before any verification.
func TestVerifyRefusesMalformedSignatureLength(t *testing.T) {
	for _, tc := range curveCases {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		toVerify := []byte("signed bytes")
		p, _ := ecdsaParamsFor(tc.alg)
		der, err := ecdsa.SignASN1(rand.Reader, key, p.digest(toVerify))
		if err != nil {
			t.Fatal(err)
		}
		fixed, err := signBytes(tc.alg, key, toVerify)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyBytes(tc.alg, &key.PublicKey, toVerify, fixed); err != nil {
			t.Fatalf("alg %d: a well-formed signature failed: %v", tc.alg, err)
		}
		for name, sig := range map[string][]byte{
			"DER":        der,
			"one short":  fixed[:len(fixed)-1],
			"one long":   append(append([]byte{}, fixed...), 0),
			"64 octets":  make([]byte, 64),
			"96 octets":  make([]byte, 96),
			"132 octets": make([]byte, 132),
			"empty":      nil,
		} {
			if len(sig) == 2*tc.size {
				continue
			}
			if err := verifyBytes(tc.alg, &key.PublicKey, toVerify, sig); err == nil {
				t.Errorf("alg %d: a %s signature verified", tc.alg, name)
			}
		}
		zero := make([]byte, 2*tc.size)
		if err := verifyBytes(tc.alg, &key.PublicKey, toVerify, zero); err == nil {
			t.Errorf("alg %d: an all-zero signature verified", tc.alg)
		}
	}
}

// AlgForKey names each supported key's algorithm, and refuses any
// other with an error naming the curve or type.
func TestAlgForKey(t *testing.T) {
	for _, tc := range curveCases {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if alg, err := AlgForKey(&key.PublicKey); err != nil || alg != tc.alg {
			t.Errorf("%s: %d, %v", tc.curve.Params().Name, alg, err)
		}
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if alg, err := AlgForKey(edPub); err != nil || alg != EdDSA {
		t.Errorf("Ed25519: %d, %v", alg, err)
	}
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AlgForKey(&p224.PublicKey); err == nil || !strings.Contains(err.Error(), "P-224") {
		t.Errorf("P-224: %v", err)
	}
	if _, err := AlgForKey(&ecdsa.PublicKey{}); err == nil || !strings.Contains(err.Error(), "unknown curve") {
		t.Errorf("no curve: %v", err)
	}
	if _, err := AlgForKey("not a key"); err == nil || !strings.Contains(err.Error(), "string") {
		t.Errorf("string: %v", err)
	}
}
