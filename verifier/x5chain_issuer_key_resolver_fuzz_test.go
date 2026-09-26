package verifier_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// FuzzResolveMdocIssuerKey exercises
// X5ChainIssuerKeyResolver.ResolveMdocIssuerKey against arbitrary DER
// — an mdoc IssuerAuth's unprotected x5chain header is attacker-
// controlled, and its certificates are parsed and chain-validated
// before the IssuerAuth signature is checked against the leaf's key.
// Roots holds a real CA and the seeds carry a chain that validates
// against it, so mutations that keep the chain intact also reach the
// leaf's key/alg handling.
func FuzzResolveMdocIssuerKey(f *testing.F) {
	ca, caKey := testcert.CA(f, "fuzz root")
	leaf, _ := testcert.Leaf(f, "fuzz leaf", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots}

	f.Add(leaf.Raw, []byte{}, false)
	f.Add(leaf.Raw, ca.Raw, true)
	f.Add(ca.Raw, []byte{}, false)
	f.Add([]byte{}, []byte{}, false)
	f.Add([]byte{0x30, 0x00}, []byte{}, true)

	f.Fuzz(func(t *testing.T, first, second []byte, twoEntries bool) {
		x5chain := [][]byte{first}
		if twoEntries {
			x5chain = append(x5chain, second)
		}
		pub, alg, err := resolver.ResolveMdocIssuerKey(context.Background(), x5chain, "org.iso.18013.5.1.mDL")
		if err != nil {
			return
		}
		if pub == nil || alg == 0 {
			t.Fatalf("ResolveMdocIssuerKey succeeded with pub=%v alg=%d", pub, alg)
		}
	})
}
