package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func x5cOf(certs ...*x509.Certificate) map[string]any {
	chain := make([]any, len(certs))
	for i, c := range certs {
		chain[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return map[string]any{"x5c": chain}
}

// An x5c that includes the trust anchor is refused (HAIP 1.0: the
// sender leaves it out); one carrying an intermediate is accepted.
func TestX5CIssuerKeyResolver_RefusesAnchorInChain(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	mid, midKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	leaf, _ := testcert.Leaf(t, "issuer", mid, midKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	r := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	if _, _, err := r.ResolveIssuerKey(context.Background(), x5cOf(leaf, mid), map[string]any{}); err != nil {
		t.Errorf("leaf and intermediate: %v", err)
	}
	if _, _, err := r.ResolveIssuerKey(context.Background(), x5cOf(leaf, mid, root), map[string]any{}); err == nil {
		t.Error("accepted an x5c that includes the trust anchor")
	}
}

// Certificates are checked at the verification's instant
// (WithVerificationTime, which VerifyResponse sets from its Now), not
// the wall clock's.
func TestX5CIssuerKeyResolver_ChecksValidityAtVerificationTime(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Valid for an hour, two hours from now: inside the root's day.
	from := time.Now().Add(2 * time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(9), NotBefore: from, NotAfter: from.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	r := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	if _, _, err := r.ResolveIssuerKey(context.Background(), x5cOf(leaf), map[string]any{}); err == nil {
		t.Error("accepted a certificate not yet valid at the current time")
	}
	at := verifier.WithVerificationTime(context.Background(), from.Add(30*time.Minute))
	if _, _, err := r.ResolveIssuerKey(at, x5cOf(leaf), map[string]any{}); err != nil {
		t.Errorf("at a verification time within its validity: %v", err)
	}
}
