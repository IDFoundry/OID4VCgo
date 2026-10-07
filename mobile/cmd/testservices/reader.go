package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
)

// demoReader is an mdoc reader identity for the demo apps' reader mode:
// a CA, which the wallets recognize readers by (mdoc_reader_roots), and
// a reader key and certificate it issued, with the reader authentication
// extended key usage. The key is a software key handed to the app in its
// configuration: test infrastructure only.
type demoReader struct {
	caPEM, chainPEM, keyPEM string
}

func newDemoReader(name string) (demoReader, error) {
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return demoReader{}, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "testservices mdoc reader CA", Country: []string{"US"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, 30),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return demoReader{}, err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return demoReader{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return demoReader{}, err
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name, Country: []string{"US"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(0, 0, 30),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{proximity.ReaderAuthenticationEKU},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		return demoReader{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return demoReader{}, err
	}
	certPEM := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return demoReader{
		caPEM:    certPEM(caDER),
		chainPEM: certPEM(leafDER) + certPEM(caDER),
		keyPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
	}, nil
}
