package issuerapp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
)

// Files an issuer keeps in Config.StateDir.
const (
	identityFile   = "issuer-identity.pem"
	statusListFile = "status-list.json"
	// crlFile is the CA's revocation list: the certificates it has
	// revoked, and its last CRL number (democrl).
	crlFile = "issuer-crl.json"
)

// PEM block roles in identityFile.
const (
	roleHeader         = "Role"
	roleCA             = "ca"
	roleDocumentSigner = "document-signer"
	roleMetadataSigner = "metadata-signer"
)

// loadOrCreateIdentity returns the identity saved in dir, or generates
// and saves a new one when there is none or the saved one can't be
// used (staleIdentity), its certificates naming crlURL as their CRL
// distribution point.
func loadOrCreateIdentity(dir string, now time.Time, crlURL string) (issuerIdentity, error) {
	path := filepath.Join(dir, identityFile)
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case err == nil:
		id, err := parseIdentity(data)
		if err != nil {
			return issuerIdentity{}, fmt.Errorf("issuerapp: %s: %w", path, err)
		}
		reason := staleIdentity(id, now, crlURL)
		if reason == "" {
			return id, nil
		}
		// For an identity from before the CA kept its key, a one-time
		// migration: that CA can't sign a CRL. The new CA is a new
		// trust anchor.
		log.Printf("issuerapp: %s: %s; replacing it with a new CA and signers: wallets and verifiers that trust the old CA need the new one (issuer-ca.pem), and credentials it issued need issuing again", path, reason)
	case !errors.Is(err, fs.ErrNotExist):
		return issuerIdentity{}, fmt.Errorf("issuerapp: read %s: %w", path, err)
	}
	id, err := newIssuerIdentity(now, crlURL)
	if err != nil {
		return issuerIdentity{}, err
	}
	if err := saveIdentity(dir, id); err != nil {
		return issuerIdentity{}, err
	}
	return id, nil
}

// staleIdentity is why the saved identity id can't be used now, or ""
// when it can: its CA has no key to sign a CRL with, or its
// certificates name no distribution point at crlURL; its document
// signer wouldn't outlive a credential issued now (the one-year
// validity cap), or isn't yet valid at the start of today (UTC), when
// an mdoc issued now is signed (see newIssuerIdentity); or its
// certificates lack what verifiers require (a countryName on the CA,
// the mDL document signer's extended key usage).
func staleIdentity(id issuerIdentity, now time.Time, crlURL string) string {
	switch {
	case id.caKey == nil:
		return "its CA has no key (from before the demo issuer published a CRL), so it can't sign one"
	case id.caCert.KeyUsage&x509.KeyUsageCRLSign == 0 || !slices.Equal(id.caCert.CRLDistributionPoints, []string{crlURL}) ||
		!slices.Equal(id.documentSignerCert.CRLDistributionPoints, []string{crlURL}):
		return "its certificates don't name the CRL distribution point " + crlURL
	case !id.documentSignerCert.NotAfter.After(now.AddDate(1, 0, 0)):
		return "its document signer expires within a year"
	case len(id.caCert.Subject.Country) == 0 || id.documentSignerCert.NotBefore.After(credential.ValidFrom(now)) ||
		mdoc.DefaultDocumentSignerPolicy(id.documentSignerCert, nil) != nil:
		return "its certificates aren't what verifiers require now"
	}
	return ""
}

// saveIdentity writes id to dir's identityFile.
func saveIdentity(dir string, id issuerIdentity) error {
	encoded, err := encodeIdentity(id)
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, identityFile), encoded)
}

func encodeIdentity(id issuerIdentity) ([]byte, error) {
	var out []byte
	if id.caKey != nil {
		der, err := x509.MarshalECPrivateKey(id.caKey)
		if err != nil {
			return nil, fmt.Errorf("issuerapp: encode CA key: %w", err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{roleHeader: roleCA}, Bytes: der})...)
	}
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: roleCA}, Bytes: id.caCert.Raw})...)
	for _, s := range []struct {
		role string
		key  *ecdsa.PrivateKey
		cert *x509.Certificate
	}{
		{roleDocumentSigner, id.documentSigner, id.documentSignerCert},
		{roleMetadataSigner, id.metadataSigner, id.metadataSignerCert},
	} {
		der, err := x509.MarshalECPrivateKey(s.key)
		if err != nil {
			return nil, fmt.Errorf("issuerapp: encode %s key: %w", s.role, err)
		}
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{roleHeader: s.role}, Bytes: der})...)
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{roleHeader: s.role}, Bytes: s.cert.Raw})...)
	}
	return out, nil
}

// parseIdentity reads an identityFile. The CA's key may be missing —
// a file from before the CA kept it has none (staleIdentity) — but one
// there must be the CA certificate's.
func parseIdentity(data []byte) (issuerIdentity, error) {
	var id issuerIdentity
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		role := block.Headers[roleHeader]
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return issuerIdentity{}, fmt.Errorf("%s certificate: %w", role, err)
			}
			switch role {
			case roleCA:
				id.caCert = cert
			case roleDocumentSigner:
				id.documentSignerCert = cert
			case roleMetadataSigner:
				id.metadataSignerCert = cert
			}
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return issuerIdentity{}, fmt.Errorf("%s key: %w", role, err)
			}
			switch role {
			case roleCA:
				id.caKey = key
			case roleDocumentSigner:
				id.documentSigner = key
			case roleMetadataSigner:
				id.metadataSigner = key
			}
		}
	}
	if id.caCert == nil || id.documentSigner == nil || id.documentSignerCert == nil || id.metadataSigner == nil || id.metadataSignerCert == nil {
		return issuerIdentity{}, errors.New("incomplete issuer identity")
	}
	if id.caKey != nil && !id.caKey.PublicKey.Equal(id.caCert.PublicKey) {
		return issuerIdentity{}, errors.New("the CA key isn't the CA certificate's")
	}
	return id, nil
}

// writeFileAtomic replaces path with data, readable only by its owner.
func writeFileAtomic(path string, data []byte) error {
	if err := statefile.WriteAtomic(path, data); err != nil {
		return fmt.Errorf("issuerapp: %w", err)
	}
	return nil
}

// loadStatusList returns the status list saved in dir (new when there
// is none), saving it back there on every change.
func loadStatusList(dir string) (*statusList, error) {
	s := newStatusList()
	s.path = filepath.Join(dir, statusListFile)
	data, err := os.ReadFile(s.path) // #nosec G304 -- operator-supplied state directory
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("issuerapp: read %s: %w", s.path, err)
	}
	var saved []IssuedStatus
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("issuerapp: %s: %w", s.path, err)
	}
	for _, e := range saved {
		if e.Idx < 0 || e.Idx >= statusListSize {
			return nil, fmt.Errorf("issuerapp: %s: index %d is out of range", s.path, e.Idx)
		}
		e := e
		if e.Handle == "" { // saved before handles existed
			if e.Handle, err = newHandle(); err != nil {
				return nil, err
			}
		}
		s.entries[e.Idx] = &e
		if e.Revoked {
			s.revoked[e.Idx] = 1
		}
	}
	return s, nil
}

// save writes s's entries to its file, if it has one. Called with s.mu
// held.
func (s *statusList) save() error {
	if s.path == "" {
		return nil
	}
	entries := make([]IssuedStatus, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, *e)
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("issuerapp: encode status list: %w", err)
	}
	return writeFileAtomic(s.path, data)
}
