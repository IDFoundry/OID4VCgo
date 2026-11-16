package certchain

import (
	"crypto/x509"
	"testing"
)

func acceptEveryLeafForTest(*x509.Certificate, [][]*x509.Certificate) error { return nil }

func init() { RegisterNonSeparating(acceptEveryLeafForTest) }

// SeparatesRoles counts neither nil nor a registered policy as one
// that separates roles, recognising the registered policy through a
// variable holding it, and counts any other policy, a closure wrapping
// the registered one among them, as one that does.
func TestSeparatesRoles(t *testing.T) {
	held := acceptEveryLeafForTest
	signingLeaf := func(leaf *x509.Certificate, _ [][]*x509.Certificate) error {
		return CheckSigningLeaf("the certificate", leaf)
	}
	for name, tc := range map[string]struct {
		policy LeafPolicy
		want   bool
	}{
		"nil":                         {nil, false},
		"a registered policy":         {acceptEveryLeafForTest, false},
		"the registered policy, held": {held, false},
		"another policy":              {signingLeaf, true},
		"a closure":                   {func(*x509.Certificate, [][]*x509.Certificate) error { return nil }, true},
		"a wrapper of the registered": {func(l *x509.Certificate, c [][]*x509.Certificate) error { return acceptEveryLeafForTest(l, c) }, true},
	} {
		if got := SeparatesRoles(tc.policy); got != tc.want {
			t.Errorf("%s: SeparatesRoles = %t, want %t", name, got, tc.want)
		}
	}
}
