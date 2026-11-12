package jose_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
)

func genKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Verify accepts ES384 on P-384 and ES512 on P-521 (RFC 7518 §3.4),
// signed by an ECDSA signer other than this package's own.
func TestVerifyES384ES512(t *testing.T) {
	payload := []byte(`{"hello":"world"}`)
	for _, tc := range []struct {
		alg   jose.Alg
		curve elliptic.Curve
	}{
		{jose.ES256, elliptic.P256()},
		{jose.ES384, elliptic.P384()},
		{jose.ES512, elliptic.P521()},
	} {
		t.Run(string(tc.alg), func(t *testing.T) {
			key := genKey(t, tc.curve)
			compact := testjose.Sign(t, string(tc.alg), key, map[string]any{"typ": "test+jwt"}, payload)
			header, got, err := jose.Verify(tc.alg, &key.PublicKey, compact)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if string(got) != string(payload) || header["typ"] != "test+jwt" {
				t.Errorf("Verify = %v, %s", header, got)
			}
			if alg, err := jose.AlgForKey(&key.PublicKey); err != nil || alg != tc.alg {
				t.Errorf("AlgForKey = %q, %v, want %q", alg, err, tc.alg)
			}

			// A changed payload doesn't verify.
			parts := strings.Split(compact, ".")
			tampered := parts[0] + "." + "eyJoZWxsbyI6Im1vb24ifQ" + "." + parts[2]
			if _, _, err := jose.Verify(tc.alg, &key.PublicKey, tampered); err == nil {
				t.Error("Verify accepted a tampered payload")
			}
			// Nor does another key on the same curve.
			if _, _, err := jose.Verify(tc.alg, &genKey(t, tc.curve).PublicKey, compact); err == nil {
				t.Error("Verify accepted another key's signature")
			}
		})
	}
}

// Each ECDSA algorithm verifies with keys on its own curve only (RFC
// 7518 §3.4), whether the header and the expected algorithm agree with
// each other or not.
func TestVerifyRefusesAlgCurveMismatch(t *testing.T) {
	p256, p384, p521 := genKey(t, elliptic.P256()), genKey(t, elliptic.P384()), genKey(t, elliptic.P521())
	payload := []byte(`{}`)
	for name, tc := range map[string]struct {
		headerAlg string
		signer    *ecdsa.PrivateKey
		expected  jose.Alg
		want      string
	}{
		"ES512 header, P-384 key":      {"ES512", p384, jose.ES512, "ES512 requires a P-521 public key"},
		"ES384 header, P-521 key":      {"ES384", p521, jose.ES384, "ES384 requires a P-384 public key"},
		"ES384 header, P-256 key":      {"ES384", p256, jose.ES384, "ES384 requires a P-384 public key"},
		"ES256 header, P-384 key":      {"ES256", p384, jose.ES256, "ES256 requires a P-256 public key"},
		"ES512 header, P-256 key":      {"ES512", p256, jose.ES512, "ES512 requires a P-521 public key"},
		"ES384 header, ES512 expected": {"ES384", p384, jose.ES512, `header alg "ES384" does not match expected "ES512"`},
		"ES512 header, ES384 expected": {"ES512", p521, jose.ES384, `header alg "ES512" does not match expected "ES384"`},
		"ES256 header, ES384 expected": {"ES256", p256, jose.ES384, `header alg "ES256" does not match expected "ES384"`},
		"ES384 header, ES256 expected": {"ES384", p384, jose.ES256, `header alg "ES384" does not match expected "ES256"`},
		"control: ES384 on P-384":      {"ES384", p384, jose.ES384, ""},
	} {
		t.Run(name, func(t *testing.T) {
			compact := testjose.Sign(t, tc.headerAlg, tc.signer, nil, payload)
			_, _, err := jose.Verify(tc.expected, &tc.signer.PublicKey, compact)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("control: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Verify = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// A signature of the wrong length for the algorithm's curve is refused
// before it's checked: an ES512 signature is 132 bytes, not ES384's 96.
func TestVerifyRefusesSignatureOfAnotherCurve(t *testing.T) {
	p384, p521 := genKey(t, elliptic.P384()), genKey(t, elliptic.P521())
	es384 := testjose.Sign(t, "ES384", p384, nil, []byte(`{}`))
	parts := strings.Split(es384, ".")
	es512 := testjose.Sign(t, "ES512", p521, nil, []byte(`{}`))
	// ES384's header and payload, ES512's signature.
	spliced := parts[0] + "." + parts[1] + "." + strings.Split(es512, ".")[2]
	if _, _, err := jose.Verify(jose.ES384, &p384.PublicKey, spliced); err == nil || !strings.Contains(err.Error(), "length") {
		t.Errorf("Verify = %v, want a signature length error", err)
	}
}

// Sign still produces ES256 and EdDSA only.
func TestSignRefusesES384ES512(t *testing.T) {
	for alg, c := range map[jose.Alg]elliptic.Curve{jose.ES384: elliptic.P384(), jose.ES512: elliptic.P521()} {
		if _, err := jose.Sign(alg, genKey(t, c), nil, []byte(`{}`)); err == nil {
			t.Errorf("Sign(%s) succeeded", alg)
		}
		if jose.IsSupported(alg) {
			t.Errorf("IsSupported(%s) = true", alg)
		}
		if !jose.IsVerifiable(alg) {
			t.Errorf("IsVerifiable(%s) = false", alg)
		}
	}
	for _, alg := range []jose.Alg{jose.ES256, jose.EdDSA} {
		if !jose.IsVerifiable(alg) {
			t.Errorf("IsVerifiable(%s) = false", alg)
		}
	}
	for _, alg := range []jose.Alg{"", "none", "RS256", "PS256", "ES256K", "HS256", "es384"} {
		if jose.IsVerifiable(alg) {
			t.Errorf("IsVerifiable(%q) = true", alg)
		}
	}
}

func TestAlgForKey(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		pub  crypto.PublicKey
		want jose.Alg
	}{
		"P-256":   {&genKey(t, elliptic.P256()).PublicKey, jose.ES256},
		"P-384":   {&genKey(t, elliptic.P384()).PublicKey, jose.ES384},
		"P-521":   {&genKey(t, elliptic.P521()).PublicKey, jose.ES512},
		"Ed25519": {edPub, jose.EdDSA},
		"P-224":   {&genKey(t, elliptic.P224()).PublicKey, ""},
		"RSA":     {&rsaKey.PublicKey, ""},
	} {
		got, err := jose.AlgForKey(tc.pub)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%s: AlgForKey = %q, want an error", name, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: AlgForKey = %q, %v, want %q", name, got, err, tc.want)
		}
	}
}
