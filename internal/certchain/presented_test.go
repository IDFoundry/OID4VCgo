package certchain

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// pkiKey is a signer of the type named: "P-256", "P-521", "RSA-3584".
func pkiKey(t testing.TB, kind string) crypto.Signer {
	t.Helper()
	var (
		k   crypto.Signer
		err error
	)
	switch kind {
	case "P-256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P-384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P-521":
		k, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var rsaOverBound = sync.OnceValues(func() ([2]*rsa.PrivateKey, error) {
	var keys [2]*rsa.PrivateKey
	for i := range keys {
		k, err := rsa.GenerateKey(rand.Reader, MaxPresentedRSABits+64)
		if err != nil {
			return keys, err
		}
		keys[i] = k
	}
	return keys, nil
})

// costlyKeys is two distinct keys of kind, "P-521" or "RSA" (over
// MaxPresentedRSABits; generated once, they're slow to make).
func costlyKeys(t testing.TB, kind string) (crypto.Signer, crypto.Signer) {
	t.Helper()
	if kind == "P-521" {
		return pkiKey(t, kind), pkiKey(t, kind)
	}
	keys, err := rsaOverBound()
	if err != nil {
		t.Fatal(err)
	}
	return keys[0], keys[1]
}

// pkiCert issues a certificate named cn, a CA when isCA, for pub under
// parent (self-signed when nil) with parentKey. Its serial is its own
// SAN-like discriminator, so two certificates of one name differ.
func pkiCert(t testing.TB, serial int64, cn string, isCA bool, pub crypto.PublicKey, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ders(certs ...*x509.Certificate) [][]byte {
	out := make([][]byte, len(certs))
	for i, c := range certs {
		out[i] = c.Raw
	}
	return out
}

func poolOf(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// The F-03 chain — CA certificates under a few names that issue each
// other, each told apart by its serial, none reaching an anchor — makes
// crypto/x509 try every permutation up to its cap of a hundred
// signature checks. Its names repeat, so it's refused by
// CheckPresentedOrder, which checks no signature, before any path is
// built; with one key shared, by the repeated key too.
func TestVerifyPresented_MutuallyIssuingCAsRefusedBeforePathBuilding(t *testing.T) {
	root := pkiCert(t, 1, "Trusted Root", true, pkiKey(t, "P-256").Public(), nil, pkiKey(t, "P-256"))
	for _, shared := range []bool{true, false} {
		key := pkiKey(t, "P-256")
		names := [][2]string{{"A", "B"}, {"B", "A"}, {"A", "C"}, {"C", "A"}, {"B", "C"}, {"C", "B"}, {"A", "B"}}
		certs := []*x509.Certificate{pkiCert(t, 100, "leaf", false, pkiKey(t, "P-256").Public(), &x509.Certificate{Subject: pkix.Name{CommonName: "A"}}, key)}
		for i, n := range names {
			if !shared {
				key = pkiKey(t, "P-256")
			}
			certs = append(certs, pkiCert(t, int64(i+1), n[0], true, key.Public(), &x509.Certificate{Subject: pkix.Name{CommonName: n[1]}}, key))
		}
		if err := CheckPresentedOrder(certs); err == nil {
			t.Fatalf("shared key %v: CheckPresentedOrder accepted the chain", shared)
		}
		_, _, err := VerifyChainsAt(ders(certs...), poolOf(root), time.Time{})
		if err == nil || !strings.Contains(err.Error(), "the same") {
			t.Errorf("shared key %v: VerifyChainsAt = %v, want refused for a repeated name or key", shared, err)
		}
	}
}

// A chain must be presented in order, leaf first; an ordered one verifies,
// whatever the anchor; repeated names or keys are refused.
func TestVerifyPresented_Order(t *testing.T) {
	rootKey, aKey, bKey := pkiKey(t, "P-256"), pkiKey(t, "P-256"), pkiKey(t, "P-256")
	root := pkiCert(t, 1, "root", true, rootKey.Public(), nil, rootKey)
	a := pkiCert(t, 2, "A", true, aKey.Public(), root, rootKey)
	b := pkiCert(t, 3, "B", true, bKey.Public(), a, aKey)
	leaf := pkiCert(t, 4, "leaf", false, pkiKey(t, "P-256").Public(), b, bKey)
	roots := poolOf(root)

	tests := map[string]struct {
		chain []*x509.Certificate
		want  string
	}{
		"in order":             {[]*x509.Certificate{leaf, b, a}, ""},
		"in order, root added": {[]*x509.Certificate{leaf, b, a, root}, ""},
		"out of order":         {[]*x509.Certificate{leaf, a, b}, "in order"},
		"gap":                  {[]*x509.Certificate{leaf, a}, "in order"},
		"repeated":             {[]*x509.Certificate{leaf, b, a, a}, "the same"},
		"leaf only":            {[]*x509.Certificate{leaf}, "does not verify"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, chains, err := VerifyChainsAt(ders(tc.chain...), roots, time.Time{})
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want == "" && (len(chains) != 1 || !chains[0][len(chains[0])-1].Equal(root)):
				t.Fatalf("got %d paths, want the one to root", len(chains))
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// A path crypto/x509 would find only by leaving the presented
// intermediate for an anchor of the same name and another key is
// refused: the presented chain, checked from its top down, isn't the
// one that verifies.
func TestVerifyPresented_OnlyThroughThePresentedChain(t *testing.T) {
	realKey, fakeKey, rootKey := pkiKey(t, "P-256"), pkiKey(t, "P-256"), pkiKey(t, "P-256")
	anchor := pkiCert(t, 1, "issuing CA", true, realKey.Public(), nil, realKey)
	root := pkiCert(t, 2, "root", true, rootKey.Public(), nil, rootKey)
	impostor := pkiCert(t, 3, "issuing CA", true, fakeKey.Public(), root, rootKey)
	leaf := pkiCert(t, 4, "leaf", false, pkiKey(t, "P-256").Public(), anchor, realKey)

	if _, _, err := VerifyChainsAt(ders(leaf, impostor), poolOf(anchor, root), time.Time{}); err == nil || !strings.Contains(err.Error(), "entry 0 isn't signed by entry 1") {
		t.Errorf("err = %v, want refused as the presented chain not verifying", err)
	}
	if _, _, err := VerifyChainsAt(ders(leaf), poolOf(anchor, root), time.Time{}); err != nil {
		t.Errorf("the leaf alone under its anchor: %v", err)
	}
}

// An intermediate with a costly key (P-521, RSA over
// MaxPresentedRSABits) is refused unless an anchor the chain reaches
// has one of that type; an included anchor counts as reached.
func TestVerifyPresented_CostlyIntermediateKeys(t *testing.T) {
	for _, kind := range []string{"P-521", "RSA"} {
		t.Run(kind, func(t *testing.T) {
			interKey, rootKey := costlyKeys(t, kind)
			p256Key := pkiKey(t, "P-256")
			p256Root := pkiCert(t, 1, "P-256 root", true, p256Key.Public(), nil, p256Key)
			inter := pkiCert(t, 2, "costly intermediate", true, interKey.Public(), p256Root, p256Key)
			leaf := pkiCert(t, 3, "leaf", false, pkiKey(t, "P-256").Public(), inter, interKey)
			_, _, err := VerifyChainsAt(ders(leaf, inter), poolOf(p256Root), time.Time{})
			if err == nil || !strings.Contains(err.Error(), "no trust anchor the chain reaches has one") {
				t.Errorf("under a P-256 root: %v, want refused for its key", err)
			}

			costlyRoot := pkiCert(t, 4, "costly root", true, rootKey.Public(), nil, rootKey)
			mid := pkiCert(t, 5, "costly intermediate", true, interKey.Public(), costlyRoot, rootKey)
			leaf2 := pkiCert(t, 6, "leaf", false, pkiKey(t, "P-256").Public(), mid, interKey)
			if _, _, err := VerifyChainsAt(ders(leaf2, mid), poolOf(costlyRoot), time.Time{}); err != nil {
				t.Errorf("under an anchor of that type: %v", err)
			}
			if _, _, err := VerifyChainsAt(ders(leaf2, mid, costlyRoot), poolOf(costlyRoot), time.Time{}); err != nil {
				t.Errorf("under an included anchor of that type: %v", err)
			}
		})
	}
}

// Two presented certificates with different names and one key are
// refused before any signature check, as two with one name are.
func TestCheckPresentedOrder_RepeatedKey(t *testing.T) {
	rootKey, caKey := pkiKey(t, "P-256"), pkiKey(t, "P-256")
	root := pkiCert(t, 1, "root", true, rootKey.Public(), nil, rootKey)
	b := pkiCert(t, 2, "B", true, caKey.Public(), root, rootKey)
	a := pkiCert(t, 3, "A", true, caKey.Public(), b, caKey)
	leaf := pkiCert(t, 4, "leaf", false, pkiKey(t, "P-256").Public(), a, caKey)
	err := CheckPresentedOrder([]*x509.Certificate{leaf, a, b})
	if err == nil || !strings.Contains(err.Error(), "entries 1 and 2 have the same public key") {
		t.Errorf("CheckPresentedOrder = %v, want refused for the repeated key", err)
	}
}

// When crypto/x509 stops at its cap on signature checks — here over
// more anchors of one name than it tries — VerifyPresented's error
// wraps ErrChainBudget.
func TestVerifyPresented_ChainBudget(t *testing.T) {
	pool := x509.NewCertPool()
	for i := range 101 {
		k := pkiKey(t, "P-256")
		pool.AddCert(pkiCert(t, int64(10+i), "busy root", true, k.Public(), nil, k))
	}
	topKey := pkiKey(t, "P-256")
	top := pkiCert(t, 1, "CA", true, topKey.Public(), &x509.Certificate{Subject: pkix.Name{CommonName: "busy root"}}, pkiKey(t, "P-256"))
	leaf := pkiCert(t, 2, "leaf", false, pkiKey(t, "P-256").Public(), top, topKey)
	_, err := VerifyPresented([]*x509.Certificate{leaf, top}, x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if !errors.Is(err, ErrChainBudget) {
		t.Errorf("err = %v, want one wrapping ErrChainBudget", err)
	}
}

// A chain is anchored from its top: one whose top no anchor issued is
// refused there, for the top, whatever is below it, and one anchored at
// its top is checked from the top down, so the error names the highest
// certificate that isn't signed by the one above it.
func TestVerifyPresented_FromTheTop(t *testing.T) {
	rootKey := pkiKey(t, "P-256")
	root := pkiCert(t, 1, "root", true, rootKey.Public(), nil, rootKey)
	keys := make([]crypto.Signer, 4)
	for i := range keys {
		keys[i] = pkiKey(t, "P-256")
	}
	// leaf, CA 1, CA 2, CA 3: each named as issued by the next, and each
	// below the top signed by a key other than the next's, so no link
	// below the top verifies.
	chain := func(topParent *x509.Certificate, topSigner crypto.Signer) []*x509.Certificate {
		top := pkiCert(t, 13, "CA 3", true, keys[3].Public(), topParent, topSigner)
		ca2 := pkiCert(t, 12, "CA 2", true, keys[2].Public(), &x509.Certificate{Subject: top.Subject}, pkiKey(t, "P-256"))
		ca1 := pkiCert(t, 11, "CA 1", true, keys[1].Public(), &x509.Certificate{Subject: ca2.Subject}, pkiKey(t, "P-256"))
		leaf := pkiCert(t, 10, "leaf", false, keys[0].Public(), &x509.Certificate{Subject: ca1.Subject}, pkiKey(t, "P-256"))
		return []*x509.Certificate{leaf, ca1, ca2, top}
	}
	opts := x509.VerifyOptions{Roots: poolOf(root), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}

	untrusted := chain(&x509.Certificate{Subject: pkix.Name{CommonName: "elsewhere"}}, pkiKey(t, "P-256"))
	_, err := VerifyPresented(untrusted, opts)
	var unknown x509.UnknownAuthorityError
	if !errors.As(err, &unknown) || unknown.Cert == nil || !unknown.Cert.Equal(untrusted[3]) {
		t.Errorf("untrusted top: err = %v, want the top refused as of an unknown authority", err)
	}

	anchored := chain(root, rootKey)
	if _, err := VerifyPresented(anchored, opts); err == nil || !strings.Contains(err.Error(), "entry 2 isn't signed by entry 3") {
		t.Errorf("anchored top: err = %v, want entry 2 refused first", err)
	}
}

// Where a chain may be anchored: at the anchor included at its top, at
// an anchor that issued its top, at its top re-issued or
// cross-certified (its subject and key an anchor's), or at the
// certificate below its top when that is an anchor itself. Further
// down is refused.
func TestVerifyPresented_AnchorPositions(t *testing.T) {
	rootKey, otherKey, caKey := pkiKey(t, "P-256"), pkiKey(t, "P-256"), pkiKey(t, "P-256")
	root := pkiCert(t, 1, "root", true, rootKey.Public(), nil, rootKey)
	other := pkiCert(t, 2, "other root", true, otherKey.Public(), nil, otherKey)
	cross := pkiCert(t, 3, "root", true, rootKey.Public(), other, otherKey)
	ca := pkiCert(t, 4, "CA", true, caKey.Public(), root, rootKey)
	leaf := pkiCert(t, 5, "leaf", false, pkiKey(t, "P-256").Public(), ca, caKey)
	direct := pkiCert(t, 6, "direct leaf", false, pkiKey(t, "P-256").Public(), root, rootKey)

	tests := map[string]struct {
		chain []*x509.Certificate
		roots *x509.CertPool
		ok    bool
	}{
		"issued by the anchor":            {[]*x509.Certificate{leaf, ca}, poolOf(root), true},
		"the anchor included":             {[]*x509.Certificate{leaf, ca, root}, poolOf(root), true},
		"the anchor cross-certified":      {[]*x509.Certificate{leaf, ca, cross}, poolOf(root), true},
		"an anchor below the top":         {[]*x509.Certificate{leaf, ca, root}, poolOf(ca), true},
		"the leaf under the cross-cert":   {[]*x509.Certificate{direct, cross}, poolOf(root), true},
		"the cross-cert's issuer anchors": {[]*x509.Certificate{direct, cross, other}, poolOf(other), true},
		"an anchor two below the top":     {[]*x509.Certificate{leaf, ca, cross, other}, poolOf(ca), false},
		"the cross-cert below the top":    {[]*x509.Certificate{direct, cross, other}, poolOf(root), false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, _, err := VerifyChainsAt(ders(tc.chain...), tc.roots, time.Time{})
			if (err == nil) != tc.ok {
				t.Errorf("err = %v, want accepted %v", err, tc.ok)
			}
		})
	}
}
