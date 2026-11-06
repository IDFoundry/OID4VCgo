package issuerapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListPath is where this issuer serves its one Token Status List,
// which every credential it issues references for revocation: SD-JWT
// VCs at StatusListPath, mdocs at MdocStatusListPath. Both serve the
// same statuses; they differ only in the form a request naming none
// gets (draft-14 §8.1), JWT here and CWT there, since an mdoc reader
// may send no Accept header and expects a CWT.
const StatusListPath = "/statuslists/1"

// MdocStatusListPath is where mdocs reference the status list: the same
// list as StatusListPath, served as a CWT when the request names no
// form.
const MdocStatusListPath = StatusListPath + "/cwt"

// statusListSize is how many credentials the list can index. A
// credential's index is drawn at random from those never handed out
// (statuslist.Allocator), so the list must be much larger than the
// number issued for indices to stay unpredictable (HAIP 1.0 §6.1: "Each
// Credential MUST have its own unique, unpredictable status list
// index"): the Allocator stops at half of it.
const statusListSize = 1 << 16

// statusTokenLifetime bounds how long a served Status List Token is
// valid (exp), and statusTokenTTL how long a Relying Party may cache it
// (ttl) — short, so a revocation shows quickly in the demo.
const (
	statusTokenLifetime = 10 * time.Minute
	statusTokenTTL      = 60 // seconds
)

var errStatusListFull = errors.New("issuerapp: the status list has no unused index left")

// IssuedStatus is one issued credential's entry in this issuer's status
// list. It records no passport data.
type IssuedStatus struct {
	Idx int
	// Handle is a random name for this entry, used by the revocation
	// page instead of Idx: listing indices next to issuance times would
	// let anyone match a presented credential's index to when it was
	// issued, which unpredictable indices are meant to prevent (HAIP
	// 1.0 §6.1).
	Handle string
	Format string
	// IssuedAt is when the credential was issued. The revocation page
	// shows only its UTC day, which every credential issued that day
	// shares: a time would let a verifier holding one find its
	// entry, and revoke it.
	IssuedAt time.Time
	Revoked  bool
	// Unchecked marks a credential issued without Passive Authentication
	// (Config.AllowSampleDocument): nothing in the credential says so.
	Unchecked bool
	// Signer is the serial number of the document signer certificate
	// whose key signed the credential (signerID): revoking that signer
	// revokes the credential too (RevokeDocumentSigner). An entry saved
	// before entries named their signer is taken to be the signer's in
	// use when the issuer starts (statusList.attribute).
	Signer string `json:",omitempty"`
}

// statusList is this issuer's Token Status List (draft-14): one bit per
// credential, 1 (StatusInvalid) meaning revoked. A statuslist.Allocator
// hands its indices out and keeps their statuses, in a
// statuslist.IndexStore: at random, never the same one twice, and up to
// statuslist.DefaultFillLimit of the list. Beside the store, entries
// are the demo's own record of each issued credential, for the status
// page and for revoking a signer's credentials: the store holds only
// reservations and statuses.
type statusList struct {
	mu        sync.Mutex
	allocator *statuslist.Allocator
	uri       string // the list's: StatusListPath's URI
	entries   map[int]*IssuedStatus
	// revokedSigners are the signers revokeSigner has revoked since the
	// process started: a credential that a request already under way
	// signs with one of them is revoked as its index is allocated.
	revokedSigners map[string]bool
	path           string // where entries are saved on every change; "" keeps them in memory
}

// newStatusList is the list at uri, its indices and statuses in store,
// with no entries.
func newStatusList(store statuslist.IndexStore, uri string) *statusList {
	return &statusList{
		allocator: &statuslist.Allocator{
			Lists:     []statuslist.AllocatorList{{URI: uri, Size: statusListSize}},
			Store:     store,
			FillLimit: statuslist.DefaultFillLimit,
		},
		uri: uri, entries: map[int]*IssuedStatus{}, revokedSigners: map[string]bool{},
	}
}

// ref is idx's reference in the list.
func (s *statusList) ref(idx int) statuslist.StatusListRef {
	return statuslist.StatusListRef{Idx: uint64(idx), URI: s.uri} // #nosec G115 -- idx is from Allocate, in [0, statusListSize)
}

// allocate reserves a random, never-before-allocated index for a
// credential of format, issued unchecked or not, signed by signer
// (signerID). It returns errStatusListFull once the list reaches its
// fill limit.
func (s *statusList) allocate(ctx context.Context, format string, unchecked bool, signer string, now time.Time) (int, error) {
	idxs, err := s.allocateN(ctx, 1, format, unchecked, signer, now)
	if err != nil {
		return 0, err
	}
	return idxs[0], nil
}

// allocateN reserves n indices as allocate does one, for a batch of n
// credentials, in one statuslist.Allocator.AllocateN: one store round
// trip, and one save of the entries. On an error none of them has an
// entry; the indices stay reserved, as every allocated one does.
func (s *statusList) allocateN(ctx context.Context, n int, format string, unchecked bool, signer string, now time.Time) ([]int, error) {
	handles := make([]string, n)
	for i := range handles {
		handle, err := newHandle()
		if err != nil {
			return nil, err
		}
		handles[i] = handle
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refs, err := s.allocator.AllocateN(ctx, n)
	switch {
	case errors.Is(err, statuslist.ErrListsFull):
		return nil, fmt.Errorf("%w (%w)", errStatusListFull, err)
	case err != nil:
		return nil, err
	}
	idxs := make([]int, len(refs))
	for i, ref := range refs {
		idxs[i] = int(ref.Idx) // #nosec G115 -- below statusListSize
	}
	drop := func() {
		for _, idx := range idxs {
			delete(s.entries, idx)
		}
	}
	for i, ref := range refs {
		// A signer revoked while the request was under way: its
		// credentials are revoked from the start. Should that fail, they
		// aren't issued.
		e := &IssuedStatus{Idx: idxs[i], Handle: handles[i], Format: format, IssuedAt: now, Unchecked: unchecked, Signer: signer, Revoked: s.revokedSigners[signer]}
		if e.Revoked {
			if err := s.allocator.SetStatus(ctx, ref, statuslist.StatusInvalid); err != nil {
				drop()
				return nil, err
			}
		}
		s.entries[idxs[i]] = e
	}
	if err := s.save(); err != nil {
		drop()
		return nil, err
	}
	return idxs, nil
}

// release drops the entry of an index whose credential wasn't issued
// after all. The index itself stays reserved in the store: the
// Allocator never hands one out twice, so nothing frees one (draft-14
// §13.3).
func (s *statusList) release(idx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, idx)
	if err := s.save(); err != nil {
		log.Printf("issuerapp: %v", err)
	}
}

// revoke sets idx's credential INVALID; false if no credential has it.
// Called with s.mu held.
func (s *statusList) revoke(ctx context.Context, idx int) (bool, error) {
	e, ok := s.entries[idx]
	if !ok {
		return false, nil
	}
	if err := s.allocator.SetStatus(ctx, s.ref(idx), statuslist.StatusInvalid); err != nil {
		return true, err
	}
	e.Revoked = true
	if err := s.save(); err != nil {
		// The store holds the revocation, and loading the entries
		// takes it from there.
		log.Printf("issuerapp: %v (the credential is revoked on the status list)", err)
	}
	return true, nil
}

// revokeSigner revokes every credential signer (signerID) signed, and
// any it's yet to sign, saving the list before it returns. It returns
// how many it revoked.
func (s *statusList) revokeSigner(ctx context.Context, signer string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedSigners[signer] = true
	n := 0
	for idx, e := range s.entries {
		if e.Signer != signer || e.Revoked {
			continue
		}
		if err := s.allocator.SetStatus(ctx, s.ref(idx), statuslist.StatusInvalid); err != nil {
			return n, err
		}
		e.Revoked = true
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.save()
}

// attribute names signer as the signer of every entry naming none:
// those saved before entries recorded their signer, taken to be the
// signer's in use when the issuer starts. One that an earlier signer
// signed is refused anyway: that signer was revoked, or its CA
// replaced.
func (s *statusList) attribute(signer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.Signer == "" {
			e.Signer = signer
		}
	}
}

// revokeHandle revokes the credential whose entry has handle; false if
// none does.
func (s *statusList) revokeHandle(ctx context.Context, handle string) (bool, error) {
	if handle == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for idx, e := range s.entries {
		if e.Handle == handle {
			return s.revoke(ctx, idx)
		}
	}
	return false, nil
}

// newHandle is a random IssuedStatus.Handle.
func newHandle() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// statuses is every index's status, read from the store: what the
// list's publishers serve.
func (s *statusList) statuses(ctx context.Context) ([]uint8, error) {
	return s.allocator.Statuses(s.uri)(ctx)
}

// snapshot copies the list's entries, newest first.
func (s *statusList) snapshot() []IssuedStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]IssuedStatus, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, *e)
	}
	slices.SortFunc(entries, func(a, b IssuedStatus) int { return b.IssuedAt.Compare(a.IssuedAt) })
	return entries
}

// withStatus points one credential's claims at idx in this issuer's
// status list: an SD-JWT VC at its JWT URI, an mdoc at its CWT one.
func (a *App) withStatus(c *issuer.CredentialInstance, idx int) {
	ref := statuslist.StatusListRef{Idx: uint64(idx), URI: a.statusListURI} // #nosec G115 -- idx is from allocate, in [0, statusListSize)
	if c.SDJWTClaims != nil {
		c.SDJWTClaims.Status = ref.Claim()
	}
	if c.MdocClaims != nil {
		c.MdocClaims.Status = &mdoc.StatusListRef{Idx: ref.Idx, URI: a.mdocStatusListURI}
	}
}

// statusPublishers serve the Status List Token at uri and mdocURI,
// signed by the document signer key with its certificate cert in the
// token's x5c/x5chain (HAIP 1.0), in the form the Accept header asks
// for. When it names neither, the first serves a JWT (SD-JWT VC
// requires a JWT Status List Token) and the second a CWT (an mdoc's). A
// token's sub is its URI, so each URI has its own Publisher.
func (a *App) statusPublishers(key *ecdsa.PrivateKey, cert *x509.Certificate) (jwt, cwt *statuslist.Publisher) {
	publisher := func(uri string, form statuslist.Form) *statuslist.Publisher {
		return &statuslist.Publisher{
			URI: uri, Signer: key, Chain: documentChain(cert),
			// Both URIs serve the one list the Allocator hands out.
			Statuses:    a.statusList.statuses,
			DefaultForm: form,
			Lifetime:    statusTokenLifetime, TTL: statusTokenTTL * time.Second, Now: a.now,
			// With a database, the token is shared through it, as
			// processes serving one list would share it; nil otherwise.
			Tokens: a.stores.statusTokens,
		}
	}
	return publisher(a.statusListURI, statuslist.FormJWT), publisher(a.mdocStatusListURI, statuslist.FormCWT)
}

type statusPage struct {
	Header        demoui.Header
	URI           string
	Entries       []IssuedStatus
	Notifications []NotificationEvent
	// Signer is the current document signer, CRLURL where its CA
	// serves its CRL, and RevokedSigners the signers it has revoked.
	Signer         signerInfo
	CRLURL         string
	RevokedSigners []democrl.Revoked
}

var statusTemplate = parsePage("status", pageHead+`</head><body>
{{template "site-header" .Header}}
<main>
<h1>Issued credentials</h1>
<p>Every credential this issuer has issued references its status list: an SD-JWT VC at <code>{{.URI}}</code>, an mdoc at <code>{{.URI}}/cwt</code>, the same list served as a CWT by default. Revoking one flips its bit; a verifier checking the list then rejects it.</p>
{{if .Entries}}
<ul class="entries">
{{range .Entries}}<li class="card entry">
<p class="badges"><span class="badge">{{formatName .Format}}</span> {{if .Revoked}}<span class="badge bad">✗ Revoked</span>{{else}}<span class="badge ok">✓ Valid</span>{{end}}{{if .Unchecked}} <span class="badge warn">⚠ Sample — issued without Passive Authentication</span>{{end}}</p>
<dl class="facts"><dt>Issued</dt><dd><time datetime="{{.IssuedAt.UTC.Format "2006-01-02"}}">{{.IssuedAt.UTC.Format "2006-01-02"}}</time></dd></dl>
{{if not .Revoked}}<details class="confirm"><summary class="btn secondary danger"><span class="when-closed">Revoke…</span><span class="when-open">Cancel</span></summary>
<form method="post" action="/demo/status/revoke"><input type="hidden" name="handle" value="{{.Handle}}">
<p class="note">Revoking can't be undone: every verifier checking the status list rejects this credential from then on.</p>
<button class="btn danger">Confirm revoke</button></form>
</details>{{end}}
</li>
{{end}}</ul>
{{else}}
<p class="card empty">None yet.</p>
{{end}}
<h2>What the wallets reported</h2>
<p>After receiving a credential, the wallet tells this issuer whether it kept it (OID4VCI 1.0 §11, the Notification Endpoint).</p>
{{if .Notifications}}
<ol class="timeline">
{{range .Notifications}}<li><time datetime="{{.At.Format "2006-01-02T15:04:05Z07:00"}}">{{.At.Format "15:04:05"}}</time> {{eventBadge .Event}} <code>{{.Event}}</code>{{with .Description}} <span class="note">— {{.}}</span>{{end}}</li>
{{end}}</ol>
{{else}}
<p class="card empty">None yet.</p>
{{end}}
<h2 id="signer">Document signer</h2>
<p>Every credential, and the status list, is signed by the issuer's document signer, which the demo CA certified. The CA publishes a Certificate Revocation List at <code>{{.CRLURL}}</code>, the distribution point its certificates name. Revoking the document signer, as an issuer does when its key is compromised, revokes every credential it signed on the status list, adds it to that CRL, and has the CA certify a new one. Credentials issued from then on verify as before. Every credential the revoked signer signed is refused by each verifier, and shown as revoked by each wallet, that checks its status, and by each that has fetched the CRL since.</p>
<div class="card">
<dl class="facts"><dt>Serial number</dt><dd><code>{{.Signer.Serial}}</code></dd><dt>Valid until</dt><dd>{{.Signer.NotAfter}}</dd></dl>
<details class="confirm"><summary class="btn secondary danger"><span class="when-closed">Revoke document signer…</span><span class="when-open">Cancel</span></summary>
<form method="post" action="/demo/signer/revoke">
<p class="note">Revoking can't be undone: every credential this signer signed is revoked on the status list and refused from then on, and its holders have to receive them again.</p>
<button class="btn danger">Confirm revoke</button></form>
</details>
</div>
{{if .RevokedSigners}}
<h3>Revoked document signers</h3>
<ul class="entries">
{{range .RevokedSigners}}<li class="card entry"><p class="badges"><span class="badge bad">✗ Revoked</span></p>
<dl class="facts"><dt>Serial number</dt><dd><code>{{.Serial}}</code></dd><dt>Revoked</dt><dd><time datetime="{{.RevokedAt.UTC.Format "2006-01-02T15:04:05Z07:00"}}">{{.RevokedAt.UTC.Format "2006-01-02 15:04"}} UTC</time></dd></dl></li>
{{end}}</ul>
{{end}}
<p class="note">Demo only: anyone who can reach this page can revoke. Entries record no passport data, and don't show the credentials' status list indices. They're kept across restarts only under <code>cmd/demo</code>.</p>
</main>
`+pageFoot)

// IssuedStatuses lists every credential this issuer has issued, newest
// first, with its status list index and whether it's revoked.
func (a *App) IssuedStatuses() []IssuedStatus {
	return a.statusList.snapshot()
}

func (a *App) handleStatusPage(w http.ResponseWriter, _ *http.Request) {
	renderPage(w, http.StatusOK, statusTemplate, statusPage{
		Header: a.header(pathStatus), URI: a.statusListURI, Entries: a.IssuedStatuses(), Notifications: a.Notifications(),
		Signer: a.signerInfo(), CRLURL: a.crlURL, RevokedSigners: a.RevokedSigners(),
	}, true)
}

// handleRevoke revokes one credential. A cross-origin form post is
// refused, so another site can't revoke through a visitor's browser.
func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		a.writeHTMLError(w, http.StatusForbidden, "cross-origin revocation refused")
		return
	}
	switch found, err := a.statusList.revokeHandle(r.Context(), r.FormValue("handle")); {
	case err != nil:
		log.Printf("issuerapp: revoke a credential: %v", err)
		a.writeHTMLError(w, http.StatusInternalServerError, "the credential couldn't be revoked")
		return
	case !found:
		a.writeHTMLError(w, http.StatusBadRequest, "unknown credential")
		return
	}
	s := a.current()
	for _, p := range []*statuslist.Publisher{s.jwtList, s.cwtList} {
		p.Invalidate() // serve the revocation at once
	}
	if a.cfg.OnRevoke != nil {
		a.cfg.OnRevoke()
	}
	http.Redirect(w, r, "/demo/status", http.StatusSeeOther)
}

// credentialFormat is the format of credential configuration id.
func credentialFormat(id string) string {
	if id == MdocConfigurationID {
		return mdoc.CredentialFormat
	}
	return sdjwtvc.CredentialFormat
}
