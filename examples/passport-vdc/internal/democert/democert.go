// Package democert creates the passport-vdc demo's X.509 certificates.
package democert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
)

// Create signs tmpl with parentKey (self-signed when parent is nil),
// giving it a random serial.
func Create(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, parentKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, fmt.Errorf("democert: certificate serial: %w", err)
	}
	tmpl.SerialNumber = serial
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		return nil, fmt.Errorf("democert: create certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}
