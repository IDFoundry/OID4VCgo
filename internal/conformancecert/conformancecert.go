// Package conformancecert builds throwaway self-signed key material
// for the conformance/*/scripts/generate-config generators — never
// for production use, and deliberately not internal/testcert (that
// one builds a *x509.Certificate for tests to hold in memory; these
// generators need PEM text to write into a JSON config file).
package conformancecert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

// SelfSignedPEM generates a fresh EC P-256 key and a self-signed
// leaf certificate for it (commonName, dnsNames, valid from an hour
// ago to 10 years out), returning both PEM-encoded.
func SelfSignedPEM(commonName string, dnsNames []string) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyPEM, err = ECKeyPEM(key)
	if err != nil {
		return "", "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), keyPEM, nil
}

// GenerateECKeyPEM generates a fresh EC P-256 key and returns its
// PEM encoding.
func GenerateECKeyPEM() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	return ECKeyPEM(key)
}

// ECKeyPEM PEM-encodes an already-generated EC private key.
func ECKeyPEM(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})), nil
}
