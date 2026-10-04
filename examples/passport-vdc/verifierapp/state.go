package verifierapp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
)

// identities are the verifier's request-signing identities: one per
// scenario, each a key and a certificate naming the scenario's relying
// party, issued by the verifier CA wallets trust, or for an untrusted
// scenario by a CA they don't. The CA keys are discarded once the
// certificates are made (HAIP 1.0 §5: the certificate signing a request
// must not be self-signed); a certificate's hash is its scenario's
// x509_hash client identifier.
type identities struct {
	ca, untrustedCA *x509.Certificate
	signers         map[Scenario]signer
}

type signer struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

// identityFile is the file a verifier keeps its identities in, in
// Config.StateDir.
const identityFile = "verifier-identity.pem"

// PEM block roles in identityFile: the CAs, and "signer:" + a scenario.
const (
	roleHeader      = "Role"
	roleCA          = "ca"
	roleUntrustedCA = "untrusted-ca"
	roleSignerPre   = "signer:"
)

// renewBefore is how long before a signing certificate expires saved
// identities are replaced with new ones.
const renewBefore = 30 * 24 * time.Hour

// loadIdentities returns the verifier's identities: kept in dir when
// set, so wallets that trust its CA still do after a restart; generated
// afresh otherwise. Saved ones are replaced, all together, when any
// scenario's is missing or names another relying party, or a
// certificate expires within renewBefore.
func loadIdentities(dir string, now time.Time) (identities, error) {
	if dir == "" {
		return newIdentities(now)
	}
	path := filepath.Join(dir, identityFile)
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case err == nil:
		ids, err := parseIdentities(data)
		if err != nil {
			return identities{}, fmt.Errorf("verifierapp: %s: %w", path, err)
		}
		if ids.current(now) {
			return ids, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return identities{}, fmt.Errorf("verifierapp: read %s: %w", path, err)
	}
	ids, err := newIdentities(now)
	if err != nil {
		return identities{}, err
	}
	encoded, err := ids.encode()
	if err != nil {
		return identities{}, err
	}
	if err := statefile.WriteAtomic(path, encoded); err != nil {
		return identities{}, fmt.Errorf("verifierapp: %w", err)
	}
	return ids, nil
}

// current reports whether ids has an identity for every scenario, named
// for its relying party, none expiring within renewBefore.
func (ids identities) current(now time.Time) bool {
	for _, s := range Scenarios {
		info, _ := s.Info()
		sg, ok := ids.signers[s]
		if !ok || sg.cert.Subject.CommonName != info.Verifier || !sg.cert.NotAfter.After(now.Add(renewBefore)) {
			return false
		}
	}
	return true
}

// newIdentities generates a trusted and an untrusted CA, and an identity
// for each scenario under the one its trust calls for.
func newIdentities(now time.Time) (identities, error) {
	ids := identities{signers: map[Scenario]signer{}}
	ca, caKey, err := newCA(now, "passport-vdc demo verifier CA")
	if err != nil {
		return identities{}, err
	}
	untrustedCA, untrustedKey, err := newCA(now, "passport-vdc demo untrusted verifier CA")
	if err != nil {
		return identities{}, err
	}
	ids.ca, ids.untrustedCA = ca, untrustedCA
	for _, s := range Scenarios {
		info, _ := s.Info()
		parent, parentKey := ca, caKey
		if !info.Trusted {
			parent, parentKey = untrustedCA, untrustedKey
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return identities{}, fmt.Errorf("verifierapp: key: %w", err)
		}
		cert, err := democert.Create(&x509.Certificate{
			Subject:   pkix.Name{CommonName: info.Verifier, Organization: []string{"IDFoundry demo"}},
			NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
			KeyUsage: x509.KeyUsageDigitalSignature,
		}, parent, &key.PublicKey, parentKey)
		if err != nil {
			return identities{}, fmt.Errorf("verifierapp: %w", err)
		}
		ids.signers[s] = signer{key: key, cert: cert}
	}
	return ids, nil
}

func newCA(now time.Time, name string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: CA key: %w", err)
	}
	cert, err := democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: name, Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
	}, nil, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: %w", err)
	}
	return cert, key, nil
}

func (ids identities) encode() ([]byte, error) {
	var out []byte
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleCA}, Bytes: ids.ca.Raw})...)
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleUntrustedCA}, Bytes: ids.untrustedCA.Raw})...)
	for _, s := range Scenarios {
		sg := ids.signers[s]
		der, err := x509.MarshalECPrivateKey(sg.key)
		if err != nil {
			return nil, fmt.Errorf("verifierapp: encode %s key: %w", s, err)
		}
		role := map[string]string{roleHeader: roleSignerPre + string(s)}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: role, Bytes: der})...)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: role, Bytes: sg.cert.Raw})...)
	}
	return out, nil
}

// parseIdentities reads an identityFile: the two CA certificates, and
// for each scenario a key with its certificate, which must be for that
// key and issued by the CA the scenario's trust calls for. A scenario
// with no identity in it is left out, for current to catch.
func parseIdentities(data []byte) (identities, error) {
	ids := identities{signers: map[Scenario]signer{}}
	keys := map[Scenario]*ecdsa.PrivateKey{}
	certs := map[Scenario]*x509.Certificate{}
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		role := block.Headers[roleHeader]
		scenario := Scenario(strings.TrimPrefix(role, roleSignerPre))
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return identities{}, fmt.Errorf("%s certificate: %w", role, err)
			}
			switch {
			case role == roleCA:
				ids.ca = c
			case role == roleUntrustedCA:
				ids.untrustedCA = c
			case strings.HasPrefix(role, roleSignerPre):
				certs[scenario] = c
			}
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return identities{}, fmt.Errorf("%s key: %w", role, err)
			}
			if strings.HasPrefix(role, roleSignerPre) {
				keys[scenario] = k
			}
		}
	}
	if ids.ca == nil || ids.untrustedCA == nil {
		return identities{}, errors.New("incomplete verifier identities")
	}
	for s, cert := range certs {
		info, known := s.Info()
		key := keys[s]
		if !known {
			continue
		}
		if key == nil || !key.PublicKey.Equal(cert.PublicKey) {
			return identities{}, fmt.Errorf("%s: the signing certificate isn't for its key", s)
		}
		parent := ids.ca
		if !info.Trusted {
			parent = ids.untrustedCA
		}
		if err := cert.CheckSignatureFrom(parent); err != nil {
			return identities{}, fmt.Errorf("%s: the signing certificate isn't its CA's: %w", s, err)
		}
		ids.signers[s] = signer{key: key, cert: cert}
	}
	return ids, nil
}
