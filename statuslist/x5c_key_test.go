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
)

// CheckX5C refuses a signer whose key it can't verify with, saying
// why, before trying the signature.
func TestCheckX5C_UnsupportedSignerKey(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, signKey := testcert.Leaf(t, "the key that signs", ca, caKey)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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
		"P-384": {&p384.PublicKey, "token signer: an ECDSA key on P-384"},
		"RSA":   {&rsaKey.PublicKey, "token signer: unsupported key type *rsa.PublicKey"},
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
