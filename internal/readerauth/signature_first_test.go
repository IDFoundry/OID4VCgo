package readerauth

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// countingRevocation passes every path, counting the checks: one per
// verified path, so none means the chain wasn't verified.
type countingRevocation struct{ n *int }

func (c countingRevocation) CheckRevocation(context.Context, certrevocation.Check) error {
	*c.n++
	return nil
}

// A reader signature is checked with its presented leaf before its
// chain is verified: one that fails costs no path building.
func TestVerify_SignatureBeforeChain(t *testing.T) {
	ca, caKey := testcert.CA(t, "reader CA")
	leaf, leafKey := testcert.Leaf(t, "reader", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	var checks int
	trust := Trust{Roots: roots, Revocation: countingRevocation{&checks}}
	sig, err := cose.SignDetached(cose.ES256, leafKey, cose.Headers{}, cose.Headers{X5Chain: [][]byte{leaf.Raw}}, []byte("signed"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(sig, []byte("other"), trust); err == nil || !strings.Contains(err.Error(), "reader signature") {
		t.Errorf("err = %v, want a signature failure", err)
	}
	if checks != 0 {
		t.Errorf("the chain was verified for a signature that fails")
	}
	if _, err := Verify(sig, []byte("signed"), trust); err != nil || checks != 1 {
		t.Errorf("the genuine signature: %v, %d revocation checks; want accepted after one", err, checks)
	}
}
