package issuer_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// New checks the SD-JWT signer's certificate before anything is issued
// with it: its key is the signer's, its chain is in order without the
// anchor, and in production it's CA-issued.
func TestNewChecksSDJWTSignerCertificate(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	mid, midKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	leaf, leafKey := testcert.Leaf(t, "issuer", mid, midKey)
	selfSigned, selfSignedKey := testcert.SelfSignedLeaf(t, "self-signed issuer")
	_, otherKey := testcert.Leaf(t, "other", mid, midKey)
	// A CA key rollover's chain: the new CA signed with the old key,
	// then the old CA, one subject twice.
	newMid, newMidKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	newWithOld := testcert.CrossCertify(t, newMid, mid, midKey)
	rolledLeaf, rolledLeafKey := testcert.Leaf(t, "issuer", newMid, newMidKey)
	for name, tc := range map[string]struct {
		signer     *issuer.SDJWTSigner
		production bool
		refused    string
	}{
		"chain":                        {signer: &issuer.SDJWTSigner{Signer: leafKey, Alg: jose.ES256, IssuerCertificate: leaf, IssuerIntermediates: []*x509.Certificate{mid}}},
		"another key's certificate":    {signer: &issuer.SDJWTSigner{Signer: otherKey, Alg: jose.ES256, IssuerCertificate: leaf}, refused: "isn't the signer's"},
		"anchor in the chain":          {signer: &issuer.SDJWTSigner{Signer: leafKey, Alg: jose.ES256, IssuerCertificate: leaf, IssuerIntermediates: []*x509.Certificate{mid, root}}, refused: "self-signed"},
		"a CA key rollover's chain":    {signer: &issuer.SDJWTSigner{Signer: rolledLeafKey, Alg: jose.ES256, IssuerCertificate: rolledLeaf, IssuerIntermediates: []*x509.Certificate{newWithOld, mid}}, refused: "the same subject name"},
		"intermediates without a leaf": {signer: &issuer.SDJWTSigner{Signer: leafKey, Alg: jose.ES256, IssuerIntermediates: []*x509.Certificate{mid}}, refused: "needs issuer_certificate"},
		"self-signed, development":     {signer: &issuer.SDJWTSigner{Signer: selfSignedKey, Alg: jose.ES256, IssuerCertificate: selfSigned}},
		"self-signed, production":      {signer: &issuer.SDJWTSigner{Signer: selfSignedKey, Alg: jose.ES256, IssuerCertificate: selfSigned}, production: true, refused: "self-signed"},
		"CA-issued, production":        {signer: &issuer.SDJWTSigner{Signer: leafKey, Alg: jose.ES256, IssuerCertificate: leaf, IssuerIntermediates: []*x509.Certificate{mid}}, production: true},
	} {
		var cfg issuer.Config
		var deps issuer.Dependencies
		if tc.production {
			cfg, deps = productionIssuer(t)
		} else {
			cfg, deps = validConfig(t), validDependencies(t)
		}
		deps.SDJWTSigner = tc.signer
		_, err := issuer.New(cfg, deps)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want refused (%s)", name, err, tc.refused)
		}
	}
}

// Signed metadata carries the intermediates after the certificate in
// x5c, and refuses a self-signed certificate (HAIP 1.0 §4.1).
func TestSignMetadataJWS_Chain(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	mid, midKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	leaf, leafKey := testcert.Leaf(t, "issuer", mid, midKey)
	meta := newTestIssuer(t, validConfig(t), validDependencies(t)).Metadata()
	signed, err := issuer.SignMetadataJWS(meta, leafKey, jose.ES256, leaf, mid)
	if err != nil {
		t.Fatalf("SignMetadataJWS: %v", err)
	}
	header, _, err := jose.DecodeUnverified(signed)
	if err != nil {
		t.Fatal(err)
	}
	if x5c, _ := header["x5c"].([]any); len(x5c) != 2 {
		t.Errorf("x5c has %d entries, want the certificate and the intermediate", len(x5c))
	}
	selfSigned, selfSignedKey := testcert.SelfSignedLeaf(t, "self-signed issuer")
	if _, err := issuer.SignMetadataJWS(meta, selfSignedKey, jose.ES256, selfSigned); err == nil {
		t.Error("signed metadata with a self-signed certificate")
	}
}
