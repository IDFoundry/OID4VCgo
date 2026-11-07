package appattest

import (
	"crypto/elliptic"
	"crypto/sha256"
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
