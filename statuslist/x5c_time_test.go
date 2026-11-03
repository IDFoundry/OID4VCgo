package statuslist

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A token signer's certificates are checked at VerifyOptions.Now, as the
// token's own times are: a list signed by a certificate that has since
// expired is valid at a time inside its validity, and isn't at the
// current time.
func TestX5C_SignerCertificateCheckedAtNow(t *testing.T) {
	then := time.Now().Add(-30 * 24 * time.Hour).Truncate(time.Second)
	cert := func(tmpl *x509.Certificate, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		t.Helper()
		tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
		tmpl.NotBefore, tmpl.NotAfter = then.Add(-time.Hour), then.Add(time.Hour)
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	caKey, key := testKey(t), testKey(t)
	ca := cert(&x509.Certificate{Subject: pkix.Name{CommonName: "past root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, &caKey.PublicKey, caKey)
	leaf := cert(&x509.Certificate{Subject: pkix.Name{CommonName: "past signer"}, KeyUsage: x509.KeyUsageDigitalSignature}, ca, &key.PublicKey, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	sl, err := New(Bits1, []uint8{0}, "")
	if err != nil {
		t.Fatal(err)
	}
	claims := TokenClaims{Sub: x5cTestURI, Iat: then.Unix(), StatusList: sl}
	ref := StatusListRef{Idx: 0, URI: x5cTestURI}
	atThen := VerifyOptions{UnboundSigner: AnyListSigner, Now: func() time.Time { return then }}

	jwt, err := IssueTokenX5C(key, jose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckX5C(jwt, roots, ref, atThen); err != nil {
		t.Errorf("JWT, at a time inside the certificate's validity: %v", err)
	}
	if _, _, err := CheckX5C(jwt, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("JWT, at the current time: accepted a list whose signer's certificate has expired")
	}

	cwt, err := IssueTokenCWTX5Chain(key, cose.ES256, claims, []*x509.Certificate{leaf})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckCWTX5Chain(cwt, roots, ref, atThen); err != nil {
		t.Errorf("CWT, at a time inside the certificate's validity: %v", err)
	}
	if _, _, err := CheckCWTX5Chain(cwt, roots, ref, VerifyOptions{UnboundSigner: AnyListSigner}); err == nil {
		t.Error("CWT, at the current time: accepted a list whose signer's certificate has expired")
	}
}
