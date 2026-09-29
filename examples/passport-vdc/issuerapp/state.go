package issuerapp

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// Files an issuer keeps in Config.StateDir.
const (
	identityFile   = "issuer-identity.pem"
	statusListFile = "status-list.json"
)

// PEM block roles in identityFile.
const (
	roleHeader         = "Role"
	roleCA             = "ca"
	roleDocumentSigner = "document-signer"
	roleMetadataSigner = "metadata-signer"
)

// loadOrCreateIdentity returns the identity saved in dir, or generates
// and saves a new one when there is none or its signers wouldn't outlive
// a credential issued now (the one-year validity cap).
func loadOrCreateIdentity(dir string, now time.Time) (issuerIdentity, error) {
	path := filepath.Join(dir, identityFile)
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case err == nil:
		id, err := parseIdentity(data)
		if err != nil {
			return issuerIdentity{}, fmt.Errorf("issuerapp: %s: %w", path, err)
		}
		if id.documentSignerCert.NotAfter.After(now.AddDate(1, 0, 0)) {
			return id, nil
		}
	case !errors.Is(err, fs.ErrNotExist):
		return issuerIdentity{}, fmt.Errorf("issuerapp: read %s: %w", path, err)
	}
	id, err := newIssuerIdentity(now)
	if err != nil {
		return issuerIdentity{}, err
	}
	encoded, err := encodeIdentity(id)
	if err != nil {
		return issuerIdentity{}, err
	}
	if err := writeFileAtomic(path, encoded); err != nil {
		return issuerIdentity{}, err
	}
	return id, nil
}

func encodeIdentity(id issuerIdentity) ([]byte, error) {
	var out []byte
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
	return id, nil
}

// writeFileAtomic replaces path with data, readable only by its owner.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("issuerapp: write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("issuerapp: write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("issuerapp: write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("issuerapp: write %s: %w", path, err)
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
