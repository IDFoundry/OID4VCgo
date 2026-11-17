package androidkey_test

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// TestVerify_AnchorBeforeLinks: a chain is anchored before any link
// below its top is checked, and its links are then checked from the
// top down. A chain no root anchors is refused as such whatever its
// links, and one a root anchors is refused at its highest broken link,
// so an anonymous registration's chain of attacker CAs, on any curve,
// costs no check with their keys.
func TestVerify_AnchorBeforeLinks(t *testing.T) {
	good := newChain(t, goodSpec(t), chainOpts{})
	ext := goodSpec(t).encode(t)
	// Each certificate below the root named as issued by the one above
	// it but signed by another key: no link verifies.
	interKey := newKey(t, elliptic.P521())
	inter := issue(t, certTemplate("Test Attestation Intermediate", 30, true), &x509.Certificate{Subject: good.root.Subject}, newKey(t, elliptic.P521()), &interKey.PublicKey)
	leaf := makeLeaf(t, &x509.Certificate{Subject: inter.Subject}, newKey(t, elliptic.P521()), &good.leafKey.PublicKey, ext, 31)

	v := verifierFor(t, good)
	if _, err := v.Verify(context.Background(), [][]byte{leaf.Raw, inter.Raw}, testChallenge); !errors.Is(err, androidkey.ErrUntrustedRoot) {
		t.Errorf("unanchored: err = %v, want %v", err, androidkey.ErrUntrustedRoot)
	}
	_, err := v.Verify(context.Background(), [][]byte{leaf.Raw, inter.Raw, good.der[2]}, testChallenge)
	if !errors.Is(err, androidkey.ErrChainSignature) || !strings.Contains(err.Error(), "certificate 1 isn't signed by certificate 2") {
		t.Errorf("anchored: err = %v, want certificate 1 refused first", err)
	}
}
