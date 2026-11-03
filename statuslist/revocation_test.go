package statuslist

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// VerifyOptions.Revocation refuses a Status List Token, in either form,
// whose signer's certificate is revoked.
func TestX5C_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "status list test CA")
	leaf, leafKey := testcert.Leaf(t, "status list signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0}, "")
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
	testcert.RunRevocationCases(t, ca, caKey, leaf, func(t *testing.T, revocation certrevocation.Checker) error {
		opts := VerifyOptions{UnboundSigner: AnyListSigner, Revocation: revocation}
		if _, _, err := CheckX5C(jwt, roots, ref, opts); err != nil {
			return err
		}
		_, _, err := CheckCWTX5Chain(cwt, roots, ref, opts)
		return err
	})
}

type revocationCtxKey struct{}

// recordingChecker is a certrevocation.Checker recording the context
// it's asked with.
type recordingChecker struct{ got *context.Context }

func (c recordingChecker) CheckRevocation(ctx context.Context, _ certrevocation.Check) error {
	*c.got = ctx
	return nil
}

// Checker.Check asks Options.Revocation with its own context, so a
// Checker sees the request's deadline and values.
func TestChecker_RevocationContext(t *testing.T) {
	srv, roots := statusServer(t)
	var got context.Context
	c := Checker{
		Fetcher: Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: roots,
		Options: VerifyOptions{UnboundSigner: AnyListSigner, Revocation: recordingChecker{&got}},
	}
	ctx := context.WithValue(context.Background(), revocationCtxKey{}, "request")
	for _, cwt := range []bool{false, true} {
		got = nil
		if _, _, err := c.Check(ctx, StatusListRef{URI: srv.URL + "/statuslists/1"}, cwt); err != nil {
			t.Fatal(err)
		}
		if got == nil || got.Value(revocationCtxKey{}) != "request" {
			t.Errorf("cwt=%v: Options.Revocation wasn't asked with Check's context", cwt)
		}
	}
}
