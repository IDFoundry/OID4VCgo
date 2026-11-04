// Package democrl publishes the passport-vdc demo CAs' Certificate
// Revocation Lists (RFC 5280 §5).
//
// Each demo CA that relying parties check for revocation keeps its key
// and serves one complete, direct CRL at the distribution point its
// certificates name, as ISO/IEC 18013-5 Annex B has an IACA do (B.1
// names the distribution point in the IACA and document signer
// certificates; B.2 profiles the CRL). That is the form
// certrevocation.CRLs and certrevocation.Refresher accept, and the
// mobile library's RefreshCRLs: no delta CRL indicator, no issuing
// distribution point, no critical extension beyond the CRL number and
// authority key identifier, and a nextUpdate.
//
// A list is signed when first asked for, and again once half its
// validity (Validity) has passed or a certificate is revoked; until
// then the same signed list is served, so a relying party fetching it
// twice sees it unchanged. Each signing takes the next CRL number,
// recorded in the CA's state file before the list is served, so the
// number never repeats or goes backwards across restarts: a relying
// party holding a list refuses one with a lower number (or an earlier
// thisUpdate) as a replay.
package democrl

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
)

// Validity is how long a list is current for: its nextUpdate is this
// long after its thisUpdate. Short, so a revocation reaches a relying
// party that refreshes on the list's schedule within the hour (the
// mobile library refreshes halfway to nextUpdate, at most an hour
// apart; certrevocation.Refresher's Run waits no longer than an hour
// either), and a list taken before a revocation can be replayed for an
// hour at most. A phone that hasn't refreshed for longer refuses the
// CA's certificates until it does, failing closed.
const Validity = time.Hour

// ContentType is a DER CRL's media type (RFC 5280 §4.2.1.13, RFC 2585).
const ContentType = "application/pkix-crl"

// Revoked is one certificate a CA has revoked.
type Revoked struct {
	// Serial is the certificate's serial number, in decimal.
	Serial string `json:"serial"`
	// Subject is the certificate's subject, for the demo's pages.
	Subject string `json:"subject"`
	// RevokedAt is when it was revoked.
	RevokedAt time.Time `json:"revoked_at"`
}

// state is what a CA's state file holds.
type state struct {
	// CA is the SHA-256 of the CA certificate the state is for, hex: a
	// file left by another CA (a demo identity made again) is ignored.
	CA string `json:"ca"`
	// Number is the CRL number of the last list signed, in decimal.
	Number  string    `json:"number"`
	Revoked []Revoked `json:"revoked"`
}

// CA is one demo CA's revocation list: the certificates it has revoked,
// and the list it serves.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	path string // its state file; "" keeps it in memory
	now  func() time.Time

	mu      sync.Mutex
	number  *big.Int // the last CRL number signed
	revoked []Revoked
	signed  *x509.RevocationList // the list served, until it's due again
}

// Open returns the revocation list of the CA cert, signed with key,
// kept in the state file at path ("" keeps it in memory), with now as
// the clock (nil: time.Now). A state file left by another CA is
// replaced, logged.
func Open(path string, cert *x509.Certificate, key *ecdsa.PrivateKey, now func() time.Time) (*CA, error) {
	switch {
	case cert == nil || key == nil:
		return nil, errors.New("democrl: a CA certificate and its key are required")
	case !key.PublicKey.Equal(cert.PublicKey):
		return nil, errors.New("democrl: the key isn't the CA certificate's")
	case cert.KeyUsage&x509.KeyUsageCRLSign == 0:
		return nil, fmt.Errorf("democrl: %q has no cRLSign key usage", cert.Subject)
	}
	if now == nil {
		now = time.Now
	}
	c := &CA{cert: cert, key: key, path: path, now: now, number: new(big.Int)}
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied state directory
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return c, nil
	case err != nil:
		return nil, fmt.Errorf("democrl: read %s: %w", path, err)
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("democrl: %s: %w", path, err)
	}
	if s.CA != fingerprint(cert) {
		log.Printf("democrl: %s is for another CA than %q: starting its revocation list afresh", path, cert.Subject)
		return c, nil
	}
	if _, ok := c.number.SetString(s.Number, 10); !ok || c.number.Sign() < 0 {
		return nil, fmt.Errorf("democrl: %s: CRL number %q", path, s.Number)
	}
	for _, r := range s.Revoked {
		if _, ok := new(big.Int).SetString(r.Serial, 10); !ok {
			return nil, fmt.Errorf("democrl: %s: serial %q", path, r.Serial)
		}
	}
	c.revoked = s.Revoked
	return c, nil
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// Certificate is the CA's certificate.
func (c *CA) Certificate() *x509.Certificate { return c.cert }

// Revoke adds cert, one this CA issued, to its list, recorded in its
// state file before it returns: the next list served names it. A
// certificate revoked already is left as it is.
func (c *CA) Revoke(cert *x509.Certificate) error {
	if err := cert.CheckSignatureFrom(c.cert); err != nil {
		return fmt.Errorf("democrl: %q wasn't issued by %q: %w", cert.Subject, c.cert.Subject, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	serial := cert.SerialNumber.String()
	if slices.ContainsFunc(c.revoked, func(r Revoked) bool { return r.Serial == serial }) {
		return nil
	}
	next := append(slices.Clone(c.revoked), Revoked{Serial: serial, Subject: cert.Subject.String(), RevokedAt: c.now().UTC().Truncate(time.Second)})
	if err := c.save(c.number, next); err != nil {
		return err
	}
	c.revoked, c.signed = next, nil
	return nil
}

// Revoked lists the certificates this CA has revoked, oldest first.
func (c *CA) Revoked() []Revoked {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.revoked)
}

// List returns the list to serve now: the one signed last, unless half
// its validity has passed or a revocation came since, when a new one is
// signed under the next CRL number, recorded first.
func (c *CA) List() (*x509.RevocationList, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.signed != nil && now.Before(c.signed.ThisUpdate.Add(Validity/2)) {
		return c.signed, nil
	}
	number := new(big.Int).Add(c.number, big.NewInt(1))
	// Recorded before it's used: a list served is never followed, after
	// a restart, by another under the same number.
	if err := c.save(number, c.revoked); err != nil {
		return nil, err
	}
	c.number = number
	entries := make([]x509.RevocationListEntry, len(c.revoked))
	for i, r := range c.revoked {
		serial, _ := new(big.Int).SetString(r.Serial, 10) // checked by Open and Revoke
		entries[i] = x509.RevocationListEntry{SerialNumber: serial, RevocationTime: r.RevokedAt}
	}
	thisUpdate := now.UTC().Truncate(time.Second)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                thisUpdate,
		NextUpdate:                thisUpdate.Add(Validity),
		RevokedCertificateEntries: entries,
	}, c.cert, c.key)
	if err != nil {
		return nil, fmt.Errorf("democrl: sign the CRL of %q: %w", c.cert.Subject, err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("democrl: %w", err)
	}
	c.signed = list
	return list, nil
}

// ServeHTTP serves the list, DER. Its fetchers revalidate each time
// (no-cache), so a list signed after a revocation reaches them at once
// through a caching proxy too.
func (c *CA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	list, err := c.List()
	if err != nil {
		log.Printf("%v", err)
		http.Error(w, "the CRL isn't available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodGet {
		_, _ = w.Write(list.Raw)
	}
}

// save writes number and revoked to c's state file, if it has one.
// Called with c.mu held.
func (c *CA) save(number *big.Int, revoked []Revoked) error {
	if c.path == "" {
		return nil
	}
	data, err := json.Marshal(state{CA: fingerprint(c.cert), Number: number.String(), Revoked: revoked})
	if err != nil {
		return fmt.Errorf("democrl: encode: %w", err)
	}
	if err := statefile.WriteAtomic(c.path, data); err != nil {
		return fmt.Errorf("democrl: %w", err)
	}
	return nil
}
