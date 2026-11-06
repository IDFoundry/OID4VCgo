package mobile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// crlSet holds the Certificate Revocation Lists the revocation checks
// of a Wallet or ProximityReader read, replaced whole by SetCRLs: CRLs
// expire (their nextUpdate), so an app fetches fresh ones and hands
// them over without rebuilding the wallet.
type crlSet struct {
	// mu orders replacements, each checked against the lists before it.
	mu    sync.Mutex
	lists atomic.Pointer[[]*x509.RevocationList]
	// issuers are the certificates of the CAs that issued certificates
	// pinned in the roots (certrevocation.CRLs.Issuers): a pinned leaf's
	// CRL is verified against its CA, which isn't on its path.
	issuers []*x509.Certificate
	// known are the CA certificates the configuration names: issuers,
	// each distribution point's issuer and the CA certificates in the
	// roots of the roles "revocation" names. A list naming one of them
	// must be signed by it, and only a list one of them signed is a
	// floor (see set). Set at construction only.
	known []*x509.Certificate

	// points are the distribution points refresh fetches (RefreshCRLs),
	// with refreshCfg's settings, and now its clock, nil for time.Now.
	// Set at construction only.
	points     []crlPoint
	refreshCfg crlRefreshConfig
	now        func() time.Time
	// jitter returns a random duration in [0, n), spreading next_refresh;
	// nil means rand.N. Tests set it.
	jitter func(n time.Duration) time.Duration

	// refreshMu guards refreshers and failures. refreshers are the
	// points' Refreshers, in points order, built at the first refresh and
	// kept, so each fetch is conditional on the last list's ETag or
	// Last-Modified and all of them share one client's connections;
	// failures counts each point's consecutive failed fetches, for its
	// backoff.
	refreshMu  sync.Mutex
	refreshers []*certrevocation.Refresher
	failures   []int
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
	s.known = s.issuers
	return s, nil
}

// set replaces s's lists with pemText's. A list naming a CA s knows
// (s.known) that it didn't sign is refused: whoever can forge one (over
// the plain http distribution points usually are) could otherwise make
// it the newest list of that CA, refusing every genuine one after it.
// A list older than the one held from the same CA's key — an earlier
// thisUpdate, or a lower CRL number — is refused too: a CRL fetched over
// plain http could otherwise be replayed to un-revoke a certificate
// revoked since, while still before its nextUpdate. Either way the lists
// are left as they were. Only a list a CA s knows signed is held to
// that, or holds others to it: a list from another CA (an intermediate
// CA's, met only on a chain) is checked against its CA's key when a
// certificate is, but can't be verified here.
func (s *crlSet) set(pemText string) error {
	lists, err := parseCRLs(pemText)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var held []*x509.RevocationList
	if p := s.lists.Load(); p != nil {
		held = *p
	}
	heldSigners := s.signers(held)
	for i, l := range lists {
		signer, err := s.signer(l)
		if err != nil {
			return fmt.Errorf("CRL %d (%q): %w", i, l.Issuer, err)
		}
		if signer == nil {
			continue
		}
		for j, h := range held {
			if heldSigners[j] != nil && sameKey(signer, heldSigners[j]) && olderCRL(l, h) {
				return fmt.Errorf("CRL %d (%q) is older than the one held for its CA", i, l.Issuer)
			}
		}
	}
	s.lists.Store(&lists)
	return nil
}

// errCRLNotSigned is a list naming a CA the configuration has that the
// CA didn't sign.
var errCRLNotSigned = errors.New("it names a CA the configuration has, which didn't sign it")

// signer returns the CA certificate of s.known that signed l, nil when
// none names l's issuer, or errCRLNotSigned when one does but none
// verifies it.
func (s *crlSet) signer(l *x509.RevocationList) (*x509.Certificate, error) {
	named := false
	for _, ca := range s.known {
		if !bytes.Equal(ca.RawSubject, l.RawIssuer) {
			continue
		}
		named = true
		if l.CheckSignatureFrom(ca) == nil {
			return ca, nil
		}
	}
	if named {
		return nil, errCRLNotSigned
	}
	return nil, nil
}

// signers returns each of lists' signer (see signer), nil for a list
// no CA s knows signed.
func (s *crlSet) signers(lists []*x509.RevocationList) []*x509.Certificate {
	out := make([]*x509.Certificate, len(lists))
	for i, l := range lists {
		out[i], _ = s.signer(l)
	}
	return out
}

// sameKey reports whether a and b are one CA's name and key: lists
// either signed share a rollback floor.
func sameKey(a, b *x509.Certificate) bool {
	return bytes.Equal(a.RawSubject, b.RawSubject) && bytes.Equal(a.RawSubjectPublicKeyInfo, b.RawSubjectPublicKeyInfo)
}

// learn adds cas to the CA certificates s knows, then drops each list
// held that names one of them without its signature: a list a version
// before this one held, and the app persisted, which would otherwise
// stay the newest list of its CA. It runs at construction only.
func (s *crlSet) learn(cas []*x509.Certificate) {
	for _, ca := range cas {
		if !slices.ContainsFunc(s.known, ca.Equal) {
			s.known = append(s.known, ca)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.lists.Load()
	if p == nil {
		return
	}
	kept := slices.DeleteFunc(slices.Clone(*p), func(l *x509.RevocationList) bool {
		_, err := s.signer(l)
		return err != nil
	})
	s.lists.Store(&kept)
}

// sameCRLIssuer reports whether a and b are lists of the same CA: the
// same issuer name and, where both say, the same key.
func sameCRLIssuer(a, b *x509.RevocationList) bool {
	if !bytes.Equal(a.RawIssuer, b.RawIssuer) {
		return false
	}
	return len(a.AuthorityKeyId) == 0 || len(b.AuthorityKeyId) == 0 || bytes.Equal(a.AuthorityKeyId, b.AuthorityKeyId)
}

// olderCRL reports whether l was issued before held: by its CRL number,
// where both have one (RFC 5280 §5.2.3: monotonically increasing), and
// otherwise by thisUpdate.
func olderCRL(l, held *x509.RevocationList) bool {
	if l.Number != nil && held.Number != nil {
		return l.Number.Cmp(held.Number) < 0
	}
	return l.ThisUpdate.Before(held.ThisUpdate)
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

// revocationRoles checks roles, the configuration key key's list of
// revocation roles, names only roles in known, each once, and returns
// whether each known role is named.
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
