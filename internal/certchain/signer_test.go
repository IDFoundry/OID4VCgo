package certchain

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

// BothPolicies passes only what both pass, and a nil one passes all.
func TestBothPolicies(t *testing.T) {
	pass := func(*x509.Certificate, [][]*x509.Certificate) error { return nil }
	refuse := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("refused") }
	for name, tc := range map[string]struct {
		first, second func(*x509.Certificate, [][]*x509.Certificate) error
		ok            bool
	}{
		"first nil":      {nil, refuse, false},
		"second nil":     {refuse, nil, false},
		"both pass":      {pass, pass, true},
		"second refuses": {pass, refuse, false},
		"first refuses":  {refuse, pass, false},
	} {
		if err := BothPolicies(tc.first, tc.second)(nil, nil); (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	called := false
	second := func(*x509.Certificate, [][]*x509.Certificate) error { called = true; return nil }
	if err := BothPolicies(refuse, second)(nil, nil); err == nil || called {
		t.Errorf("first refusing: %v, second run %v; want refused before second", err, called)
	}
	if BothPolicies(nil, nil) != nil {
		t.Error("BothPolicies(nil, nil) isn't nil")
	}
}

// A signer's chain through a CA key rollover — the new key's
// certificate signed with the old key, then the old key's — verifies
// link by link but names one subject twice, which verifiers of a
// presented chain refuse: CheckPresentedChain, and so SignerChainDERs,
// refuses it, so an issuer, verifier, Wallet Provider or status list
// signer configured with it learns at startup.
func TestCheckPresentedChain_RepeatedSubject(t *testing.T) {
	rootKey, oldKey, newKey, leafKey := pkiKey(t, "P-256"), pkiKey(t, "P-256"), pkiKey(t, "P-256"), pkiKey(t, "P-256")
	root := pkiCert(t, 1, "root", true, rootKey.Public(), nil, rootKey)
	oldCA := pkiCert(t, 2, "CA", true, oldKey.Public(), root, rootKey)
	newWithOld := pkiCert(t, 3, "CA", true, newKey.Public(), oldCA, oldKey)
	leaf := pkiCert(t, 4, "signer", false, leafKey.Public(), newWithOld, newKey)

	if err := newWithOld.CheckSignatureFrom(oldCA); err != nil {
		t.Fatalf("the rollover chain's links: %v", err)
	}
	err := CheckPresentedChain(leaf, []*x509.Certificate{newWithOld, oldCA})
	if err == nil || !strings.Contains(err.Error(), "the same subject name") {
		t.Errorf("CheckPresentedChain = %v, want refused for the repeated subject", err)
	}
	_, err = SignerChainDERs(leafKey, []*x509.Certificate{leaf, newWithOld, oldCA})
	if err == nil || !strings.Contains(err.Error(), "the same subject name") {
		t.Errorf("SignerChainDERs = %v, want refused for the repeated subject", err)
	}
	if err := CheckPresentedChain(leaf, []*x509.Certificate{newWithOld}); err != nil {
		t.Errorf("the chain without the old CA: %v", err)
	}
	if _, err := SignerChainDERs(leafKey, []*x509.Certificate{leaf, newWithOld}); err != nil {
		t.Errorf("the chain without the old CA, as DERs: %v", err)
	}
}
