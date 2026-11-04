package verifierapp

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
)

// Where the verifier's CAs serve their Certificate Revocation Lists,
// relative to VerifierURL: the distribution points their certificates
// name. Each is the list of one CA a wallet checks for revocation: the
// verifier CA, which issues the request-signing certificates (a
// wallet's "verifier" role); the mdoc reader CA, which issues the
// reader authentication certificates of org-iso-mdoc requests and the
// in-person reader ("mdoc_reader"); and the registrar CA, which
// issues the registrar's ("registrar"). The untrusted CA, which no
// wallet trusts, publishes none.
const (
	VerifierCRLPath  = "/verifier-ca.crl"
	ReaderCRLPath    = "/reader-ca.crl"
	RegistrarCRLPath = "/registrar-ca.crl"
)

// crlFiles are the files in Config.StateDir the CAs keep their lists'
// state in (democrl), by distribution point path.
var crlFiles = map[string]string{
	VerifierCRLPath:  "verifier-ca-crl.json",
	ReaderCRLPath:    "reader-ca-crl.json",
	RegistrarCRLPath: "registrar-ca-crl.json",
}

// openCRLs opens the revocation lists of ids' CAs, in dir ("" keeps
// them in memory), by distribution point path.
func openCRLs(dir string, ids identities, now func() time.Time) (map[string]*democrl.CA, error) {
	out := map[string]*democrl.CA{}
	for path, ca := range map[string]signer{
		VerifierCRLPath:  {cert: ids.ca, key: ids.caKey},
		ReaderCRLPath:    {cert: ids.readerCA, key: ids.readerCAKey},
		RegistrarCRLPath: {cert: ids.registrarCA, key: ids.registrarCAKey},
	} {
		state := ""
		if dir != "" {
			state = filepath.Join(dir, crlFiles[path])
		}
		list, err := democrl.Open(state, ca.cert, ca.key, now)
		if err != nil {
			return nil, fmt.Errorf("verifierapp: %w", err)
		}
		out[path] = list
	}
	return out, nil
}

// CRLHandler serves the verifier CAs' CRLs at their paths
// (VerifierCRLPath, ReaderCRLPath, RegistrarCRLPath), as this App does
// under VerifierURL: for the demo to serve them at a second address
// (cmd/demo's plain-http one).
func (a *App) CRLHandler() http.Handler {
	mux := http.NewServeMux()
	for path, list := range a.crls {
		mux.Handle("GET "+path, list)
	}
	return mux
}

// issuerCRLs is the revocation check on the demo issuer's
// certificates: each chain ending at one of the IssuerCAs that names a
// CRL distribution point is checked against the CRL served there,
// which a certrevocation.Refresher fetches — on its schedule when Run
// (RunIssuerCRLRefresh), at once when told (RefreshIssuerCRLs), and on
// a check that finds no current list held. A CA that names no
// distribution point publishes no CRL, so its chains aren't checked.
// The distribution points are read from the configured CA
// certificates, never from a presented one.
type issuerCRLs struct {
	refresher *certrevocation.Refresher // nil when no CA names a distribution point
	checker   certrevocation.CRLs
	checked   []*x509.Certificate // the CAs whose chains are checked
	urls      int
	now       func() time.Time
	mu        sync.Mutex // one fetch at a time on a check that misses
}

// newIssuerCRLs checks chains ending at cas against the CRLs at their
// http or https distribution points, fetched with client (nil: the
// hardened default, allowed loopback, as the demo serves on
// 127.0.0.1).
func newIssuerCRLs(cas []*x509.Certificate, client *http.Client, now func() time.Time) (*issuerCRLs, error) {
	c := &issuerCRLs{now: now}
	var urls []string
	bound := map[string]*x509.Certificate{}
	for _, ca := range cas {
		named := false
		for _, u := range ca.CRLDistributionPoints {
			if parsed, err := url.Parse(u); err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || bound[u] != nil {
				continue
			}
			urls, bound[u], named = append(urls, u), ca, true
		}
		if named {
			c.checked = append(c.checked, ca)
		}
	}
	if len(urls) == 0 {
		return c, nil
	}
	var err error
	c.refresher, err = certrevocation.NewRefresher(certrevocation.RefresherConfig{
		URLs: urls, Issuers: c.checked, URLIssuers: bound,
		HTTPClient: client, AllowLoopback: client == nil,
		OnError: func(u string, err error) { log.Printf("verifierapp: issuer CRL %s: %v", u, err) },
		Clock:   now,
	})
	if err != nil {
		return nil, fmt.Errorf("verifierapp: issuer CRLs: %w", err)
	}
	c.checker = certrevocation.CRLs{Lists: c.lists}
	c.urls = len(urls)
	return c, nil
}

// CheckRevocation implements certrevocation.Checker.
func (c *issuerCRLs) CheckRevocation(ctx context.Context, check certrevocation.Check) error {
	if len(check.Chain) == 0 || c.refresher == nil {
		return nil
	}
	anchor := check.Chain[len(check.Chain)-1]
	for _, ca := range c.checked {
		if bytes.Equal(anchor.Raw, ca.Raw) {
			err := c.checker.CheckRevocation(ctx, check)
			if err != nil {
				// The refusal reaches the request page only as an
				// untrusted issuer: say why here.
				log.Printf("verifierapp: refusing a credential's issuer certificate: %v", err)
			}
			return err
		}
	}
	return nil
}

// lists are the CRLs held, fetched first when one isn't held or has
// passed its nextUpdate: on the first check after a start, before the
// refresher's schedule has run, and after the issuer was out of reach
// for longer than a list lasts. A verifier serving many checks would
// rather keep fetching off the request path (Run) than make a check
// wait; the demo prefers the check to see the issuer's latest list.
func (c *issuerCRLs) lists(ctx context.Context) ([]*x509.RevocationList, error) {
	if lists, _ := c.refresher.Lists(ctx); c.allCurrent(lists) {
		return lists, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if lists, _ := c.refresher.Lists(ctx); !c.allCurrent(lists) {
		fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := c.refresher.Refresh(fetchCtx); err != nil {
			log.Printf("verifierapp: %v", err)
		}
	}
	return c.refresher.Lists(ctx)
}

// allCurrent reports whether lists holds one from every distribution
// point, each before its nextUpdate.
func (c *issuerCRLs) allCurrent(lists []*x509.RevocationList) bool {
	if len(lists) < c.urls {
		return false
	}
	now := c.now()
	for _, l := range lists {
		if !now.Before(l.NextUpdate) {
			return false
		}
	}
	return true
}

// RefreshIssuerCRLs fetches the issuer CAs' CRLs now: for the demo
// issuer running beside this verifier to call when it revokes its
// document signer (issuerapp.Config.OnSignerRevoked), so its
// credentials are refused at once rather than after the next scheduled
// fetch.
func (a *App) RefreshIssuerCRLs(ctx context.Context) error {
	if a.issuerCRLs.refresher == nil {
		return nil
	}
	a.issuerCRLs.mu.Lock()
	defer a.issuerCRLs.mu.Unlock()
	return a.issuerCRLs.refresher.Refresh(ctx)
}

// RunIssuerCRLRefresh keeps the issuer CAs' CRLs current until ctx is
// done, fetching each well before its nextUpdate, and at least hourly
// (certrevocation.Refresher.Run). Run it in a goroutine.
func (a *App) RunIssuerCRLRefresh(ctx context.Context) {
	if a.issuerCRLs.refresher != nil {
		a.issuerCRLs.refresher.Run(ctx)
	}
}
