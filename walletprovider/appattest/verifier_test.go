package appattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

func TestAppleRoot(t *testing.T) {
	roots := AppleRoots()
	if len(roots) != 1 {
		t.Fatalf("%d roots, want 1", len(roots))
	}
	r := roots[0]
	sum := sha256.Sum256(r.Raw)
	// The SHA-256 of the root Apple publishes at
	// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem.
	if got := hex.EncodeToString(sum[:]); got != "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932" {
		t.Fatalf("embedded root SHA-256 %s", got)
	}
	if r.Subject.CommonName != "Apple App Attestation Root CA" || !r.IsCA {
		t.Fatalf("root %s", r.Subject)
	}
	roots[0] = nil
	if AppleRoots()[0] == nil {
		t.Fatal("AppleRoots shares its slice")
	}
}

func TestVerifyAttestation(t *testing.T) {
	f := newFakeApple(t)
	hash := hashOf("client data")
	obj, key := f.attest(t, attSpec{clientDataHash: hash})
	att, err := f.verifier().VerifyAttestation(obj, hash)
	if err != nil {
		t.Fatal(err)
	}
	if !att.PublicKey.Equal(&key.PublicKey) || att.AppID != testAppID || att.Environment != EnvironmentProduction ||
		string(att.KeyID) != string(KeyID(&key.PublicKey)) || len(att.Chain) != 2 || string(att.Receipt) != "receipt" {
		t.Fatalf("attestation %+v", att)
	}

	v := f.verifier()
	v.AllowDevelopment = true
	obj, _ = f.attest(t, attSpec{clientDataHash: hash, aaguid: aaguidDevelopment})
	if att, err := v.VerifyAttestation(obj, hash); err != nil || att.Environment != EnvironmentDevelopment {
		t.Fatalf("development: %v, %+v", err, att)
	}
}

func TestVerifyAttestationRefuses(t *testing.T) {
	f := newFakeApple(t)
	other := newFakeApple(t)
	hash := hashOf("client data")
	for _, tc := range []struct {
		name   string
		obj    func() []byte
		v      func(*Verifier)
		hash   []byte
		target error
	}{
		{name: "another root", obj: func() []byte { o, _ := other.attest(t, attSpec{clientDataHash: hash}); return o }, target: ErrUntrustedRoot},
		{name: "expired credential certificate", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash, notAfter: time.Now().Add(time.Minute)})
			return o
		}, v: func(v *Verifier) { v.Now = func() time.Time { return time.Now().Add(time.Hour) } }, target: ErrUntrustedRoot},
		{name: "other client data", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash, nonceHash: hashOf("other")})
			return o
		}, target: ErrNonce},
		{name: "checked against other client data", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash}); return o }, hash: hashOf("other"), target: ErrNonce},
		{name: "bytes after the nonce", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash, nonceTrailer: []byte{0x00}})
			return o
		}, target: ErrMalformed},
		{name: "too large, well-formed", obj: func() []byte { return withReceiptTo(t, f, hash, MaxAttestationBytes+1) }, target: ErrMalformed},
		{name: "one certificate, anchored", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash})
			var obj attestationObject
			if err := cbor.Unmarshal(o, &obj); err != nil {
				t.Fatal(err)
			}
			obj.AttStmt.X5C = obj.AttStmt.X5C[:1]
			return mustCBOR(t, obj)
		}, v: func(v *Verifier) { v.Roots = []*x509.Certificate{f.inter} }, target: ErrMalformed},
		{name: "App ID without a bundle", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash}); return o }, v: func(v *Verifier) { v.Apps = []string{"ABCDE12345."} }, target: ErrConfig},
		{name: "no nonce", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash, noNonce: true}); return o }, target: ErrMalformed},
		{name: "another app", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash, appID: "ABCDE12345.dev.example.other"})
			return o
		}, target: ErrAppNotAllowed},
		{name: "counter", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash, counter: 1}); return o }, target: ErrCounter},
		{name: "development", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash, aaguid: aaguidDevelopment}); return o }, target: ErrEnvironment},
		{name: "unknown AAGUID", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash, aaguid: make([]byte, 16)}); return o }, target: ErrEnvironment},
		{name: "credential ID", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash, credentialID: make([]byte, 32)})
			return o
		}, target: ErrKeyID},
		{name: "P-384 key", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash, key: newKey(t, elliptic.P384()), credentialID: make([]byte, 32)})
			return o
		}, target: ErrMalformed},
		{name: "format", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash, format: "packed"}); return o }, target: ErrMalformed},
		{name: "empty", obj: func() []byte { return nil }, target: ErrMalformed},
		{name: "too large", obj: func() []byte { return make([]byte, MaxAttestationBytes+1) }, target: ErrMalformed},
		{name: "not CBOR", obj: func() []byte { return []byte{0xff} }, target: ErrMalformed},
		{name: "duplicate key", obj: func() []byte {
			// {"fmt": "apple-appattest", "fmt": "apple-appattest"}
			return append([]byte{0xa2}, append(cborText("fmt", "apple-appattest"), cborText("fmt", "apple-appattest")...)...)
		}, target: ErrMalformed},
		{name: "one certificate", obj: func() []byte {
			return mustCBOR(t, map[string]any{"fmt": "apple-appattest", "attStmt": map[string]any{"x5c": [][]byte{f.inter.Raw}}, "authData": []byte{}})
		}, target: ErrMalformed},
		{name: "certificate garbage", obj: func() []byte {
			return mustCBOR(t, map[string]any{"fmt": "apple-appattest", "attStmt": map[string]any{"x5c": [][]byte{{1}, {2}}}, "authData": []byte{}})
		}, target: ErrMalformed},
		{name: "short authenticator data", obj: func() []byte {
			o, _ := f.attest(t, attSpec{clientDataHash: hash})
			var obj attestationObject
			if err := cbor.Unmarshal(o, &obj); err != nil {
				t.Fatal(err)
			}
			obj.AuthData = obj.AuthData[:40]
			return mustCBOR(t, obj)
		}, target: ErrMalformed},
		{name: "no app", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash}); return o }, v: func(v *Verifier) { v.Apps = nil }, target: ErrConfig},
		{name: "App ID without a team", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash}); return o }, v: func(v *Verifier) { v.Apps = []string{"wallet"} }, target: ErrConfig},
		{name: "short client data hash", obj: func() []byte { o, _ := f.attest(t, attSpec{clientDataHash: hash}); return o }, hash: []byte{1}, target: ErrConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := f.verifier()
			if tc.v != nil {
				tc.v(v)
			}
			h := hash
			if tc.hash != nil {
				h = tc.hash
			}
			_, err := v.VerifyAttestation(tc.obj(), h)
			if !errors.Is(err, tc.target) {
				t.Fatalf("got %v, want %v", err, tc.target)
			}
		})
	}
}

// TestVerifyAttestationBounds: an attestation of exactly
// MaxAttestationBytes is accepted, and one whose credential
// certificate is anchored at the intermediate verifies with both
// certificates in x5c: what refuses one alone is x5c's bound.
func TestVerifyAttestationBounds(t *testing.T) {
	f := newFakeApple(t)
	hash := hashOf("client data")
	if _, err := f.verifier().VerifyAttestation(withReceiptTo(t, f, hash, MaxAttestationBytes), hash); err != nil {
		t.Fatalf("a %d-byte attestation: %v", MaxAttestationBytes, err)
	}
	o, _ := f.attest(t, attSpec{clientDataHash: hash})
	v := f.verifier()
	v.Roots = []*x509.Certificate{f.inter}
	if _, err := v.VerifyAttestation(o, hash); err != nil {
		t.Fatalf("anchored at the intermediate: %v", err)
	}
}

// withReceiptTo is a good attestation over hash, its receipt sized so
// the object is size bytes.
func withReceiptTo(t testing.TB, f *fakeApple, hash []byte, size int) []byte {
	t.Helper()
	o, _ := f.attest(t, attSpec{clientDataHash: hash})
	var obj attestationObject
	if err := cbor.Unmarshal(o, &obj); err != nil {
		t.Fatal(err)
	}
	// The receipt's length header is three bytes for any length from
	// 256 to 65535, so one adjustment lands on size.
	obj.AttStmt.Receipt = make([]byte, 1000)
	obj.AttStmt.Receipt = make([]byte, 1000+size-len(mustCBOR(t, obj)))
	out := mustCBOR(t, obj)
	if len(out) != size {
		t.Fatalf("a %d-byte attestation, want %d", len(out), size)
	}
	return out
}

func TestParseAuthData(t *testing.T) {
	base := make([]byte, authDataMinBytes)
	if _, err := parseAuthData(base, true); !errors.Is(err, ErrMalformed) {
		t.Fatalf("no attested credential flag: %v", err)
	}
	base[32] = flagAttestedCredential
	withLen := append(append(base, make([]byte, 16)...), 0x00, 0x20)
	if _, err := parseAuthData(withLen, true); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a credential ID longer than the data: %v", err)
	}
	// Attested credential data without the flag that says it's there.
	unflagged := append(make([]byte, authDataMinBytes), make([]byte, 18)...)
	if _, err := parseAuthData(unflagged, true); !errors.Is(err, ErrMalformed) {
		t.Fatalf("attested credential data without its flag: %v", err)
	}
}

func TestVerifyAssertion(t *testing.T) {
	f := newFakeApple(t)
	key := newKey(t, elliptic.P256())
	hash := hashOf("client data")
	a, err := f.verifier().VerifyAssertion(assert(t, key, testAppID, 5, hash), hash, &key.PublicKey, 4)
	if err != nil {
		t.Fatal(err)
	}
	if a.AppID != testAppID || a.Counter != 5 {
		t.Fatalf("assertion %+v", a)
	}

	otherKey := newKey(t, elliptic.P256())
	for _, tc := range []struct {
		name   string
		obj    []byte
		hash   []byte
		last   uint32
		target error
	}{
		{name: "another key", obj: assert(t, otherKey, testAppID, 5, hash), target: ErrSignature},
		{name: "other client data", obj: assert(t, key, testAppID, 5, hashOf("other")), target: ErrSignature},
		{name: "counter not larger", obj: assert(t, key, testAppID, 5, hash), last: 5, target: ErrCounter},
		{name: "another app", obj: assert(t, key, "ABCDE12345.dev.example.other", 5, hash), target: ErrAppNotAllowed},
		{name: "no signature", obj: mustCBOR(t, map[string][]byte{"authenticatorData": make([]byte, authDataMinBytes)}), target: ErrMalformed},
		{name: "short authenticator data", obj: mustCBOR(t, map[string][]byte{"signature": {1}, "authenticatorData": {1}}), target: ErrMalformed},
		{name: "not CBOR", obj: []byte{0xff}, target: ErrMalformed},
		{name: "too large", obj: make([]byte, MaxAssertionBytes+1), target: ErrMalformed},
		{name: "short client data hash", obj: assert(t, key, testAppID, 5, hash), hash: []byte{1}, target: ErrConfig},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := hash
			if tc.hash != nil {
				h = tc.hash
			}
			if _, err := f.verifier().VerifyAssertion(tc.obj, h, &key.PublicKey, tc.last); !errors.Is(err, tc.target) {
				t.Fatalf("got %v, want %v", err, tc.target)
			}
		})
	}
	if _, err := f.verifier().VerifyAssertion(assert(t, key, testAppID, 5, hash), hash, nil, 0); !errors.Is(err, ErrConfig) {
		t.Fatalf("no key: %v", err)
	}

	// The size bound, on assertions that are otherwise good.
	if _, err := f.verifier().VerifyAssertion(assertSized(t, key, hash, MaxAssertionBytes), hash, &key.PublicKey, 4); err != nil {
		t.Fatalf("a %d-byte assertion: %v", MaxAssertionBytes, err)
	}
	if _, err := f.verifier().VerifyAssertion(assertSized(t, key, hash, MaxAssertionBytes+1), hash, &key.PublicKey, 4); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a %d-byte assertion: %v, want ErrMalformed", MaxAssertionBytes+1, err)
	}
}

// assertSized is a good assertion with counter 5 over hash, padded to
// size bytes.
func assertSized(t testing.TB, key *ecdsa.PrivateKey, hash []byte, size int) []byte {
	t.Helper()
	pad := size - 200
	// A signature's length varies by a byte or two: adjust the padding
	// until the assertion comes out at size.
	for range 50 {
		a := assertPadded(t, key, testAppID, 5, hash, pad)
		if len(a) == size {
			return a
		}
		pad += size - len(a)
	}
	t.Fatalf("no %d-byte assertion", size)
	return nil
}

func mustCBOR(t testing.TB, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// cborText encodes a text-string key and value pair, each shorter than
// 24 bytes.
func cborText(k, v string) []byte {
	b := append([]byte{0x60 | byte(len(k))}, k...)
	return append(append(b, 0x60|byte(len(v))), v...)
}
