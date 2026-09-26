// Package demotls provides the passport-vdc demo servers' TLS
// certificates: an operator-supplied pair, or a generated self-signed
// loopback certificate written out for clients to trust.
package demotls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// Certificate loads certFile/keyFile, or — when certFile is empty —
// generates a self-signed certificate for 127.0.0.1, ::1 and localhost
// named commonName, and writes it (PEM) to certOut.
func Certificate(certFile, keyFile, certOut, commonName string) (tls.Certificate, error) {
	if certFile != "" {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certOut, pemBytes, 0o600); err != nil { // #nosec G703 -- operator-supplied path
		return tls.Certificate{}, fmt.Errorf("write %s: %w", certOut, err)
	}
	log.Printf("generated a self-signed TLS certificate; wrote it to %s for clients to trust", certOut)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
