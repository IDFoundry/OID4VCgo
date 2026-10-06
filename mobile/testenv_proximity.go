//go:build mobiletest

package mobile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
)

// ProximityReader sets up an mdoc reader for in-person tests: it creates
// a P-256 key in keys, issues it a reader authentication certificate
// from a new test CA, and returns {"abi", "reader_config",
// "mdoc_reader_roots"}: reader_config is a NewProximityReader
// configuration accepting the TestEnv's mdocs and signing with that key,
// and mdoc_reader_roots the CA's PEM, for a wallet to recognize the
// reader by. The reader's name is "Test Reader".
func (e *TestEnv) ProximityReader(keys KeyStore) (string, error) {
	if keys == nil {
		return "", newError(CodeInvalidInput, errors.New("no KeyStore"))
	}
	id, err := keys.CreateKey(PurposeInstance)
	if err != nil {
		return "", newError(CodePlatform, err)
	}
	key, err := keyStore{keys}.load(id)
	if err != nil {
		return "", err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Reader CA", Country: []string{"US"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Reader", Country: []string{"US"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{proximity.ReaderAuthenticationEKU},
	}, ca, key.Public(), caKey)
	if err != nil {
		return "", newError(CodeInternal, fmt.Errorf("reader certificate: %w", err))
	}
	pemOf := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	cfg, _ := marshal(proximityReaderConfig{
		IssuerRoots: pemOf(e.env.IssuerCA.Raw), ReaderKeyID: id, ReaderChain: pemOf(leafDER) + pemOf(caDER),
	})
	return marshal(struct {
		result
		ReaderConfig    string `json:"reader_config"`
		MdocReaderRoots string `json:"mdoc_reader_roots"`
	}{result{ABIVersion}, cfg, pemOf(caDER)})
}
