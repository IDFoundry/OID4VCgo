package certchain

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// A chain longer than MaxChainLength is refused before any entry past
// the bound is decoded or parsed; one at the bound isn't refused for
// its length.
func TestMaxChainLength(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	roots := x509.NewCertPool()
	roots.AddCert(root)

	// leaf, then MaxChainLength-1 intermediates, the last issued by root.
	atBound := make([][]byte, MaxChainLength)
	parent, parentKey := root, rootKey
	for i := MaxChainLength - 1; i > 0; i-- {
		parent, parentKey = testcert.Intermediate(t, fmt.Sprintf("intermediate %d", i), parent, parentKey)
		atBound[i] = parent.Raw
	}
	leaf, _ := testcert.Leaf(t, "leaf", parent, parentKey)
	atBound[0] = leaf.Raw
	entries := make([]any, MaxChainLength)
	for i := range atBound {
		entries[i] = base64.StdEncoding.EncodeToString(atBound[i])
	}
	overBound := append(append([][]byte(nil), atBound...), []byte("not even a certificate"))

	if _, err := DERsFromBase64(entries); err != nil {
		t.Errorf("DERsFromBase64 at the bound: %v", err)
	}
	if _, err := DERsFromBase64(append(entries, "!")); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("DERsFromBase64 over the bound: %v, want refused for its length", err)
	}
	if _, _, err := VerifyChainsAt(atBound, roots, time.Time{}); err != nil {
		t.Errorf("VerifyChainsAt at the bound: %v", err)
	}
	if _, _, err := VerifyChainsAt(overBound, roots, time.Time{}); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("VerifyChainsAt over the bound: %v, want refused for its length", err)
	}
	if err := CheckNoAnchor(overBound); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("CheckNoAnchor over the bound: %v, want refused for its length", err)
	}
}

// CheckNoAnchor refuses a self-issued certificate after the leaf
// without checking its signature: one whose signature doesn't verify
// is refused too.
func TestCheckNoAnchor_SelfIssuedWithoutSignatureCheck(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	leaf, _ := testcert.Leaf(t, "leaf", root, rootKey)
	broken := append([]byte(nil), root.Raw...)
	broken[len(broken)-5] ^= 1
	parsed, err := x509.ParseCertificate(broken)
	if err != nil {
		t.Fatal(err)
	}
	if IsSelfSigned(parsed) {
		t.Fatal("the altered root still verifies as self-signed")
	}
	if err := CheckNoAnchor([][]byte{leaf.Raw, broken}); err == nil {
		t.Error("a self-issued certificate with a broken signature after the leaf was accepted")
	}
	// An intermediate named for itself under a different issuer name is
	// an ordinary intermediate.
	mid, _ := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "intermediate"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, root, rootKey)
	if err := CheckNoAnchor([][]byte{leaf.Raw, mid.Raw}); err != nil {
		t.Errorf("an intermediate: %v", err)
	}
}
