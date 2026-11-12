package statuslist

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testjose"
)

// CheckX5C refuses a signer whose key it can't verify with, saying
// why, before trying the signature.
func TestCheckX5C_UnsupportedSignerKey(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, signKey := testcert.Leaf(t, "the key that signs", ca, caKey)
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	claims := TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}
	for name, tc := range map[string]struct {
		pub  crypto.PublicKey
		want string
	}{
		"P-224": {&p224.PublicKey, "token signer: jose: unsupported ECDSA curve P-224"},
		"RSA":   {&rsaKey.PublicKey, "token signer: jose: unsupported public key type *rsa.PublicKey"},
	} {
		leaf := testcert.LeafFor(t, name+" signer", tc.pub, ca, caKey)
		token, err := issueToken(signKey, jose.ES256, claims, map[string]any{
			"typ": TokenTyp, "x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = CheckX5C(token, roots, StatusListRef{URI: x5cTestURI}, VerifyOptions{UnboundSigner: AnyListSigner})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error containing %q", name, err, tc.want)
		}
	}
}

// A Status List Token signed ES384 by a P-384 signer, or ES512 by a
// P-521 one, verifies; one whose header names another algorithm than
// its signer's key takes is refused.
func TestCheckX5C_ES384ES512(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{1}, "")
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"sub": x5cTestURI, "iat": time.Now().Unix(), "status_list": sl}
	keys := map[string]*ecdsa.PrivateKey{}
	for name, c := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		if keys[name], err = ecdsa.GenerateKey(c, rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	for name, tc := range map[string]struct {
		alg, crv string
		want     string
	}{
		"ES384 on P-384": {"ES384", "P-384", ""},
		"ES512 on P-521": {"ES512", "P-521", ""},
		"ES512 on P-384": {"ES512", "P-384", `header alg "ES512" does not match expected "ES384"`},
		"ES384 on P-521": {"ES384", "P-521", `header alg "ES384" does not match expected "ES512"`},
		"ES256 on P-384": {"ES256", "P-384", `header alg "ES256" does not match expected "ES384"`},
		"ES384 on P-256": {"ES384", "P-256", `header alg "ES384" does not match expected "ES256"`},
	} {
		t.Run(name, func(t *testing.T) {
			key := keys[tc.crv]
			leaf := testcert.LeafFor(t, name+" signer", &key.PublicKey, ca, caKey)
			token := testjose.SignClaims(t, tc.alg, key, map[string]any{
				"typ": TokenTyp, "x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)},
			}, payload)
			status, _, err := CheckX5C(token, roots, StatusListRef{Idx: 0, URI: x5cTestURI}, VerifyOptions{UnboundSigner: AnyListSigner})
			if tc.want == "" {
				if err != nil || status != StatusInvalid {
					t.Fatalf("CheckX5C = %v, %v, want INVALID", status, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("CheckX5C = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
