package certchain

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// rsaKey is a public key of bits with exponent e. Its modulus is a
// random odd number of that length, not a product of two primes: a
// certificate carries any key, and signature checks with it cost what
// a real one of that size does.
func rsaKey(t *testing.T, bits, e int) *rsa.PublicKey {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
	if err != nil {
		t.Fatal(err)
	}
	n.SetBit(n, bits-1, 1)
	n.SetBit(n, 0, 1)
	return &rsa.PublicKey{N: n, E: e}
}

// A presented certificate with an RSA key over MaxRSABits, or with an
// exponent other than 65537, is refused before any signature is checked
// with it, as a leaf or as an intermediate; one at MaxRSABits isn't.
func TestCheckKeySize(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for name, tc := range map[string]struct {
		key  *rsa.PublicKey
		want string // "" for accepted
	}{
		"4096 bits":       {rsaKey(t, MaxRSABits, 65537), ""},
		"4097 bits":       {rsaKey(t, MaxRSABits+1, 65537), "an RSA key of 4097 bits"},
		"65536 bits":      {rsaKey(t, 65536, 65537), "an RSA key of 65536 bits"},
		"exponent 3":      {rsaKey(t, 2048, 3), "exponent 3"},
		"exponent 2^31-1": {rsaKey(t, 2048, 1<<31-1), "exponent 2147483647"},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := testcert.LeafFor(t, "leaf", tc.key, root, rootKey)
			err := CheckKeySize(leaf)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("CheckKeySize = %v, want %q", err, tc.want)
			}
			if tc.want == "" {
				return
			}
			if _, _, err := VerifyChains([][]byte{leaf.Raw}, roots); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("VerifyChains with it as the leaf: %v", err)
			}
			if err := CheckPresentedChain(leaf, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("CheckPresentedChain with it as the leaf: %v", err)
			}
			intermediate, intermediateKey := testcert.Intermediate(t, "intermediate", root, rootKey)
			signed := testcert.LeafFor(t, "signed", &intermediateKey.PublicKey, intermediate, intermediateKey)
			bad := testcert.LeafFor(t, "bad intermediate", tc.key, root, rootKey)
			if _, _, err := VerifyChains([][]byte{signed.Raw, bad.Raw}, roots); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("VerifyChains with it as an intermediate: %v", err)
			}
			if err := CheckPresentedChain(signed, []*x509.Certificate{bad}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("CheckPresentedChain with it as an intermediate: %v", err)
			}
		})
	}
}
