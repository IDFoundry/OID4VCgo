package walletflow

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// identifierListEntry is the identifier list entry one of an mdoc's
// copies names (ISO/IEC 18013-5 §12.3.6.4), and its document signer
// path, which binds the list's signer to its issuer (§12.3.6.2).
type identifierListEntry struct {
	ref  identifierlist.Ref
	path []*x509.Certificate
}

// same reports whether e and o name the same entry of the same list.
func (e identifierListEntry) same(o identifierListEntry) bool {
	return bytes.Equal(e.ref.ID, o.ref.ID) && e.ref.URI == o.ref.URI && bytes.Equal(e.ref.Certificate, o.ref.Certificate)
}

// listKey is what binds the list e names to the signer it's checked
// against: its uri, the Certificate its MSO names and the document
// signer path. Entries with the same key share one fetched list.
func (e identifierListEntry) listKey() string {
	var b strings.Builder
	b.WriteString(e.ref.URI)
	b.WriteByte(0)
	b.Write(e.ref.Certificate)
	for _, cert := range e.path {
		b.WriteByte(0)
		b.Write(cert.Raw)
	}
	return b.String()
}

// identifierLists are the distinct identifier list entries named by
// the MSOs of those of c's copies keep accepts, read from the copies,
// verified when they were received. A copy that can't be read is an error, not one without an
// entry: its MSO may still revoke it.
func identifierLists(c StoredCredential, keep func(CredentialCopy) bool) ([]identifierListEntry, error) {
	if c.Format != mdoc.CredentialFormat {
		return nil, nil
	}
	var lists []identifierListEntry
	for _, cp := range c.AllCopies() {
		if !keep(cp) {
			continue
		}
		e, err := copyIdentifierList(c, cp)
		if err != nil {
			return nil, err
		}
		if e != nil && !slices.ContainsFunc(lists, e.same) {
			lists = append(lists, *e)
		}
	}
	return lists, nil
}

// copyIdentifierList is the identifier list entry copy cp of c names,
// nil for none.
func copyIdentifierList(c StoredCredential, cp CredentialCopy) (*identifierListEntry, error) {
	if c.Format != mdoc.CredentialFormat {
		return nil, nil
	}
	issuerSigned, err := storedIssuerSigned(cp.Credential)
	if err != nil {
		return nil, err
	}
	status, path, err := mdoc.IssuerAuthStatus(issuerSigned)
	if err != nil {
		return nil, err
	}
	if status == nil || status.IdentifierList == nil {
		return nil, nil
	}
	return &identifierListEntry{ref: identifierlist.Ref(*status.IdentifierList), path: path}, nil
}

// liveIdentifierLists are identifierLists of c's copies not yet expired
// at now.
func liveIdentifierLists(c StoredCredential, now time.Time) ([]identifierListEntry, error) {
	return identifierLists(c, func(cp CredentialCopy) bool { return copyLive(c, cp, now) })
}

// sameIdentifierLists reports whether a and b's copies name the same
// identifier list entries; false when either can't be read.
func sameIdentifierLists(a, b StoredCredential) bool {
	all := func(CredentialCopy) bool { return true }
	la, errA := identifierLists(a, all)
	lb, errB := identifierLists(b, all)
	return errA == nil && errB == nil && slices.EqualFunc(la, lb, identifierListEntry.same)
}

// checkIdentifierLists is the entries among entries, c's copies', that
// are on their identifier lists: revoked. Each list's signer must
// chain to the Certificate its MSO names, or, naming none, to the mdoc
// roots configured for c's doctype, through the CA that signed its
// document signer (identifierlist.Check). A list several copies share
// is fetched and verified once.
func (w *Wallet) checkIdentifierLists(ctx context.Context, c StoredCredential, entries []identifierListEntry) ([]identifierListEntry, error) {
	roots, _ := w.cfg.issuerTrust(c.Format, c.DocType)
	checker := identifierlist.Checker{
		Fetcher: statuslist.Fetcher{HTTP: w.deps.HTTP, AllowLoopback: w.cfg.Development},
		Roots:   roots,
		Options: identifierlist.VerifyOptions{Now: w.deps.Clock, Revocation: w.cfg.StatusRevocation},
	}
	var listed []identifierListEntry
	lists := map[string]identifierlist.TokenClaims{}
	for _, e := range entries {
		key := e.listKey()
		claims, ok := lists[key]
		if !ok {
			var err error
			if _, claims, err = checker.Check(ctx, e.ref, e.path); err != nil {
				return nil, fmt.Errorf("identifier list: %w", err)
			}
			lists[key] = claims
		}
		if claims.Contains(e.ref.ID) {
			listed = append(listed, e)
		}
	}
	return listed, nil
}
