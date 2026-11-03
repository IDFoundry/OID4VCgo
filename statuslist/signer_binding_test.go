package statuslist

import (
	"crypto/x509"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// CheckX5C and CheckCWTX5Chain refuse a check that binds the signer to
// no issuer: with neither Issuer nor IssuerKey, UnboundSigner decides
// it, and nil refuses it.
func TestCheck_UnboundSignerRefusedByDefault(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0, 1}, "")
	if err != nil {
		t.Fatal(err)
	}
	claims := TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}
	jwt, err := IssueTokenX5C(leafKey, jose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	cwt, err := IssueTokenCWTX5Chain(leafKey, cose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	refusing := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("not this issuer's") }
	for name, tc := range map[string]struct {
		opts VerifyOptions
		want string
	}{
		"zero options":          {VerifyOptions{}, "can't be bound"},
		"UnboundSigner refuses": {VerifyOptions{UnboundSigner: refusing}, "not this issuer's"},
		"AnyListSigner":         {VerifyOptions{UnboundSigner: AnyListSigner}, ""},
		"IssuerKey binds it":    {VerifyOptions{IssuerKey: &leafKey.PublicKey}, ""},
	} {
		for form, check := range map[string]func() (StatusType, TokenClaims, error){
			"jwt": func() (StatusType, TokenClaims, error) { return CheckX5C(jwt, roots, ref, tc.opts) },
			"cwt": func() (StatusType, TokenClaims, error) { return CheckCWTX5Chain(cwt, roots, ref, tc.opts) },
		} {
			status, _, err := check()
			switch {
			case tc.want == "" && (err != nil || status != StatusValid):
				t.Errorf("%s, %s: %v, %v; want VALID", name, form, status, err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("%s, %s: %v; want an error containing %q", name, form, err, tc.want)
			}
		}
	}
}

// A list too large for DefaultMaxTokenBytes verifies once
// MaxTokenBytes allows it, and MaxTokenBytes past MaxTokenBytesLimit is
// refused.
func TestCheckX5C_MaxTokenBytes(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	// A million 8-bit statuses at random don't compress: about 1.3 MiB
	// once base64url-encoded.
	statuses := make([]uint8, 1<<20)
	r := rand.New(rand.NewPCG(1, 2))
	for i := range statuses {
		statuses[i] = uint8(r.Uint32())
	}
	sl, err := New(Bits8, statuses, "")
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := IssueTokenX5C(leafKey, jose.ES256, TokenClaims{Sub: x5cTestURI, Iat: time.Now().Unix(), StatusList: sl}, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	if len(jwt) <= DefaultMaxTokenBytes {
		t.Fatalf("the token is %d bytes, within the default: the test proves nothing", len(jwt))
	}
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	opts := VerifyOptions{UnboundSigner: AnyListSigner}
	if _, _, err := CheckX5C(jwt, roots, ref, opts); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("default limit: %v, want the token refused as too large", err)
	}
	opts.MaxTokenBytes = 4 << 20
	if status, _, err := CheckX5C(jwt, roots, ref, opts); err != nil || status != StatusType(statuses[0]) {
		t.Errorf("MaxTokenBytes 4 MiB: %v, %v; want %v", status, err, StatusType(statuses[0]))
	}
	opts.MaxTokenBytes = MaxTokenBytesLimit + 1
	if _, _, err := CheckX5C(jwt, roots, ref, opts); err == nil || !strings.Contains(err.Error(), "MaxTokenBytes") {
		t.Errorf("MaxTokenBytes over the limit: %v, want a refusal naming it", err)
	}
}
