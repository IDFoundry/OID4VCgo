package androidkey_test

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// TestVerify_RootKeyIsNoAnchorByItself: carrying a root's public key
// anchors nothing, since anyone can put one in a certificate they sign
// themselves. A one-certificate "chain" whose certificate has the
// root's key and an extension of the forger's choosing is refused, as
// is a leaf with a root's key under a genuine intermediate, and a
// chain whose top has the root's key but isn't the root or signed by
// it. A re-issue of the root, self-signed by its key, still anchors.
func TestVerify_RootKeyIsNoAnchorByItself(t *testing.T) {
	good := newChain(t, goodSpec(t), chainOpts{})
	ext := goodSpec(t).encode(t)
	forger := newKey(t, elliptic.P256())
	forgerCA := issue(t, certTemplate("Forger", 20, true), nil, forger, &forger.PublicKey)
	forgedLeaf := makeLeaf(t, forgerCA, forger, good.root.PublicKey, ext, 21)
	leafWithRootKey := makeLeaf(t, good.inter, good.interKey, good.root.PublicKey, ext, 22)
	forgedRoot := issue(t, certTemplate(good.root.Subject.CommonName, 23, true), forgerCA, forger, good.root.PublicKey)
	reissuedRoot := issue(t, certTemplate(good.root.Subject.CommonName, 24, true), nil, good.rootKey, good.root.PublicKey)

	for name, tc := range map[string]struct {
		chain [][]byte
		want  error
	}{
		"forged certificate alone":         {[][]byte{forgedLeaf.Raw}, androidkey.ErrMalformed},
		"leaf with the root's key":         {[][]byte{leafWithRootKey.Raw, good.der[1], good.der[2]}, androidkey.ErrUntrustedRoot},
		"leaf with the root's key, no top": {[][]byte{leafWithRootKey.Raw, good.der[1]}, androidkey.ErrUntrustedRoot},
		"top with the root's key, forged":  {[][]byte{good.der[0], good.der[1], forgedRoot.Raw}, androidkey.ErrUntrustedRoot},
		"re-issued root":                   {[][]byte{good.der[0], good.der[1], reissuedRoot.Raw}, nil},
		"the root itself":                  {good.der, nil},
		"ending at the intermediate":       {good.der[:2], nil},
	} {
		t.Run(name, func(t *testing.T) {
			v := verifierFor(t, good)
			v.Roots = []*x509.Certificate{good.root}
			if _, err := v.Verify(context.Background(), tc.chain, testChallenge); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
