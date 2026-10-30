package mobile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// crlSet holds the Certificate Revocation Lists the revocation checks
// of a Wallet or ProximityReader read, replaced whole by SetCRLs: CRLs
// expire (their nextUpdate), so an app fetches fresh ones and hands
// them over without rebuilding the wallet.
type crlSet struct {
	lists atomic.Pointer[[]*x509.RevocationList]
	// issuers are the certificates of the CAs that issued certificates
	// pinned in the roots (certrevocation.CRLs.Issuers): a pinned leaf's
	// CRL is verified against its CA, which isn't on its path.
	issuers []*x509.Certificate
}

// newCRLSet is a crlSet holding the CRLs of crls, a configuration's
// "crls" PEM, with the CA certificates of issuers, its "crl_issuers".
func newCRLSet(crls, issuers string) (*crlSet, error) {
	s := &crlSet{}
	if err := s.set(crls); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("crls: %w", err))
	}
	var err error
	if s.issuers, err = parseCRLIssuers(issuers); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("crl_issuers: %w", err))
	}
	return s, nil
}

// set replaces s's lists with pemText's.
func (s *crlSet) set(pemText string) error {
	lists, err := parseCRLs(pemText)
	if err != nil {
		return err
	}
	s.lists.Store(&lists)
	return nil
}

// checker is a certrevocation.CRLs over s's current lists and its
// issuers. With none that apply, it fails closed
// (certrevocation.ErrNoCurrentCRL).
func (s *crlSet) checker() certrevocation.CRLs {
	return certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		if p := s.lists.Load(); p != nil {
			return *p, nil
		}
		return nil, nil
	}, Issuers: s.issuers}
}

// maxCRLs bounds how many lists one PEM text may hold: each is checked
// on every certificate chain a role verifies.
const maxCRLs = 64

// parseCRLs parses pemText's "X509 CRL" blocks. Anything else — another
// block type, text outside the blocks, a list that doesn't parse — is
// refused, so a certificate pasted in place of a CRL isn't silently
// dropped. Empty text is no lists.
func parseCRLs(pemText string) ([]*x509.RevocationList, error) {
	var lists []*x509.RevocationList
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "X509 CRL" {
			return nil, fmt.Errorf("PEM block %d is %q, not an X509 CRL", len(lists), block.Type)
		}
		list, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CRL %d: %w", len(lists), err)
		}
		if lists = append(lists, list); len(lists) > maxCRLs {
			return nil, fmt.Errorf("more than %d CRLs", maxCRLs)
		}
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("text that isn't a PEM X509 CRL block")
	}
	return lists, nil
}

// parseCRLIssuers parses pemText's "CERTIFICATE" blocks, each a CA
// that issued a certificate pinned in the roots. Anything else — another
// block type, text outside the blocks, a certificate that doesn't parse
// or isn't a CA's — is refused, as parseCRLs refuses what isn't a CRL.
// Empty text is none.
func parseCRLIssuers(pemText string) ([]*x509.Certificate, error) {
	var issuers []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("PEM block %d is %q, not a CERTIFICATE", len(issuers), block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", len(issuers), err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return nil, fmt.Errorf("certificate %d (%q) isn't a CA's", len(issuers), cert.Subject)
		}
		if issuers = append(issuers, cert); len(issuers) > maxCRLs {
			return nil, fmt.Errorf("more than %d certificates", maxCRLs)
		}
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("text that isn't a PEM CERTIFICATE block")
	}
	return issuers, nil
}

// Revocation role names, the "revocation" configuration's entries.
const (
	revocationIssuer         = "issuer"
	revocationIssuerMetadata = "issuer_metadata"
	revocationRegistrar      = "registrar"
	revocationMdocReader     = "mdoc_reader"
	revocationVerifier       = "verifier"
	revocationStatus         = "status"
)

// revocationRoles checks roles, the configuration key key's list of
// revocation roles, names only roles in known, each once, and returns
// whether each known role is named.
// revocationChoice is the revocation check of role, whose roots are
// configuration keys keys, set (inUse) or not: crls' checker when the
// configuration's "revocation" names it (named), certrevocation.NoCheck
// when its "no_revocation_check" does (declined), and otherwise nil, no
// check, which is refused for a role in use when the configuration
// requires the choice (when says when it does: "outside development").
func revocationChoice(role, keys string, inUse bool, named, declined map[string]bool, when string, crls *crlSet) (certrevocation.Checker, error) {
	switch {
	case named[role] && declined[role]:
		return nil, newError(CodeInvalidInput, fmt.Errorf("%q is named in both revocation and no_revocation_check", role))
	case named[role]:
		return crls.checker(), nil
	case declined[role]:
		return certrevocation.NoCheck{}, nil
	case inUse && when != "":
		return nil, newError(CodeInvalidInput, fmt.Errorf("%s is set: %s, name %q in revocation, checked against crls, or in no_revocation_check to decline", keys, when, role))
	}
	return nil, nil
}

func revocationRoles(key string, roles []string, known ...string) (map[string]bool, error) {
	named := make(map[string]bool, len(roles))
	for _, r := range roles {
		switch {
		case !slices.Contains(known, r):
			return nil, newError(CodeInvalidInput, fmt.Errorf("%s: %q isn't a role: want one of %q", key, r, known))
		case named[r]:
			return nil, newError(CodeInvalidInput, fmt.Errorf("%s: %q is named twice", key, r))
		}
		named[r] = true
	}
	return named, nil
}
