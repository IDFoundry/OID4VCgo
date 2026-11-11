package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

// P-384 and P-521 keys (RFC 7518 §6.2.1.1, the curves of ES384 and
// ES512) marshal, parse back, match and take RFC 7638 thumbprints as
// P-256 keys do, each coordinate the curve's field size.
func TestP384P521Keys(t *testing.T) {
	for _, tc := range []struct {
		crv   string
		curve elliptic.Curve
		size  int
	}{
		{"P-384", elliptic.P384(), 48},
		{"P-521", elliptic.P521(), 66},
	} {
		t.Run(tc.crv, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			k, err := Marshal(&key.PublicKey)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if k.Kty != "EC" || k.Crv != tc.crv {
				t.Fatalf("Marshal = %+v", k)
			}
			for name, c := range map[string]string{"x": k.X, "y": k.Y} {
				raw, err := base64.RawURLEncoding.DecodeString(c)
				if err != nil || len(raw) != tc.size {
					t.Errorf("%s is %d bytes, want %d", name, len(raw), tc.size)
				}
			}
			raw, err := json.Marshal(k)
			if err != nil {
				t.Fatal(err)
			}
			pub, err := ParsePublicKey(raw)
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			if !key.PublicKey.Equal(pub) {
				t.Error("ParsePublicKey returned another key")
			}
			if ok, err := Matches(raw, &key.PublicKey); err != nil || !ok {
				t.Errorf("Matches = %v, %v", ok, err)
			}

			got, err := k.Thumbprint()
			if err != nil {
				t.Fatalf("Thumbprint: %v", err)
			}
			sum := sha256.Sum256(fmt.Appendf(nil, `{"crv":"%s","kty":"EC","x":"%s","y":"%s"}`, tc.crv, k.X, k.Y))
			if want := base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
				t.Errorf("Thumbprint = %s, want %s", got, want)
			}

			// The coordinates of one curve under another's name are refused.
			other := "P-384"
			if tc.crv == other {
				other = "P-521"
			}
			if _, err := (JWK{Kty: "EC", Crv: other, X: k.X, Y: k.Y}).PublicKey(); err == nil {
				t.Errorf("PublicKey accepted %s coordinates as %s", tc.crv, other)
			}
			// A private member is refused, as for P-256.
			priv, err := MarshalPrivate(key)
			if err != nil {
				t.Fatal(err)
			}
			withD, err := json.Marshal(priv)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParsePublicKey(withD); err == nil {
				t.Error("ParsePublicKey accepted a JWK carrying d")
			}
		})
	}
}
