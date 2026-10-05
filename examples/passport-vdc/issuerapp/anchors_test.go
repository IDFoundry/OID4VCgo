package issuerapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"
)

// Every CA certificate in Wallet.ProviderCA becomes an anchor bound to
// the configured Wallet Provider alone; other PEM blocks are skipped,
// and data with no certificate is refused.
func TestAttesterAnchors(t *testing.T) {
	ca := func(name string) []byte {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		}, &x509.Certificate{Subject: pkix.Name{CommonName: name}}, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	data := slices.Concat(ca("one"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}}), ca("two"))
	anchors, err := attesterAnchors(data, "https://provider.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 2 {
		t.Fatalf("got %d anchors, want 2", len(anchors))
	}
	for i, a := range anchors {
		if a.Certificate == nil || !slices.Equal(a.Issuers, []string{"https://provider.example"}) {
			t.Errorf("anchor %d = %+v, want a certificate bound to the provider alone", i, a)
		}
	}
	if _, err := attesterAnchors([]byte("not PEM"), "https://provider.example"); err == nil {
		t.Error("data with no certificate: accepted")
	}
}
