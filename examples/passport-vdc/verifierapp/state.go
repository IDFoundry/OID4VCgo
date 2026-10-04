package verifierapp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
)

// identityFile is the file a verifier keeps its request-signing identity
// in, in Config.StateDir.
const identityFile = "verifier-identity.pem"

// PEM block roles in identityFile.
const (
	roleHeader = "Role"
	roleCA     = "ca"
	roleSigner = "request-signer"
)

// renewBefore is how long before its signing certificate expires a saved
// identity is replaced with a new one.
const renewBefore = 30 * 24 * time.Hour

// loadOrCreateSigningIdentity returns the request-signing identity saved
// in dir, or generates and saves a new one when there is none or its
// certificate expires within renewBefore. Wallets trust the verifier by
// its CA, so keeping it means they still do after a restart.
func loadOrCreateSigningIdentity(dir string, now time.Time) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	path := filepath.Join(dir, identityFile)
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case err == nil:
		key, cert, caCert, err := parseSigningIdentity(data)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("verifierapp: %s: %w", path, err)
		}
		if cert.NotAfter.After(now.Add(renewBefore)) {
			return key, cert, caCert, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil, fmt.Errorf("verifierapp: read %s: %w", path, err)
	}
	key, cert, caCert, err := newRequestSigningIdentity(now)
	if err != nil {
		return nil, nil, nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verifierapp: encode the signing key: %w", err)
	}
	var out []byte
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleCA}, Bytes: caCert.Raw})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{roleHeader: roleSigner}, Bytes: der})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleSigner}, Bytes: cert.Raw})...)
	if err := statefile.WriteAtomic(path, out); err != nil {
		return nil, nil, nil, fmt.Errorf("verifierapp: %w", err)
	}
	return key, cert, caCert, nil
}

// parseSigningIdentity reads an identityFile: the CA certificate, and
// the signing key with its certificate, which the CA must have issued
// and which must be for that key.
func parseSigningIdentity(data []byte) (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	var key *ecdsa.PrivateKey
	var cert, caCert *x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		role := block.Headers[roleHeader]
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%s certificate: %w", role, err)
			}
			switch role {
			case roleCA:
				caCert = c
			case roleSigner:
				cert = c
			}
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("%s key: %w", role, err)
			}
			if role == roleSigner {
				key = k
			}
		}
	}
	if key == nil || cert == nil || caCert == nil {
		return nil, nil, nil, errors.New("incomplete verifier identity")
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, nil, nil, errors.New("the signing certificate isn't for the signing key")
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return nil, nil, nil, fmt.Errorf("the signing certificate isn't the CA's: %w", err)
	}
	return key, cert, caCert, nil
}
