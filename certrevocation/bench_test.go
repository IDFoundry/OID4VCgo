package certrevocation_test

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// BenchmarkCRLs_Large checks a three-certificate chain whose leaf's CA
// publishes a CRL of a million entries, none of them the leaf.
func BenchmarkCRLs_Large(b *testing.B) {
	root, rootKey := testcert.CA(b, "root")
	inter, interKey := testcert.Intermediate(b, "intermediate", root, rootKey)
	leaf, _ := testcert.Leaf(b, "leaf", inter, interKey)
	revoked := time.Now().Add(-time.Minute)
	tmpl := &x509.RevocationList{RevokedCertificateEntries: make([]x509.RevocationListEntry, 1_000_000)}
	for i := range tmpl.RevokedCertificateEntries {
		tmpl.RevokedCertificateEntries[i] = x509.RevocationListEntry{SerialNumber: new(big.Int).Lsh(big.NewInt(int64(i+1)), 64), RevocationTime: revoked}
	}
	lists := []*x509.RevocationList{testcert.CRLFromTemplate(b, tmpl, inter, interKey), testcert.CRL(b, root, rootKey)}
	checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return lists, nil }}
	check := certrevocation.Check{Chain: []*x509.Certificate{leaf, inter, root}}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := checker.CheckRevocation(context.Background(), check); err != nil {
			b.Fatal(err)
		}
	}
}
