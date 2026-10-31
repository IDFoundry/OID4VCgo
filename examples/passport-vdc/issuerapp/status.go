package issuerapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
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
// credential's index is drawn at random from the unused ones, so the
// list must be much larger than the number issued for indices to stay
// unpredictable (HAIP 1.0 §6.1: "Each Credential MUST have its own
// unique, unpredictable status list index").
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
}

// statusList is this issuer's Token Status List (draft-14): one bit per
// credential, 1 meaning revoked.
type statusList struct {
	mu      sync.Mutex
	revoked []uint8
	entries map[int]*IssuedStatus
	path    string // where it's saved on every change; "" keeps it in memory
}

func newStatusList() *statusList {
	return &statusList{revoked: make([]uint8, statusListSize), entries: map[int]*IssuedStatus{}}
}

// allocate reserves a random unused index for a credential of format,
// issued unchecked or not.
func (s *statusList) allocate(format string, unchecked bool, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= statusListSize/2 {
		return 0, errStatusListFull
	}
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(statusListSize))
		if err != nil {
			return 0, err
		}
		idx := int(n.Int64())
		if _, used := s.entries[idx]; !used {
			handle, err := newHandle()
			if err != nil {
				return 0, err
			}
			s.entries[idx] = &IssuedStatus{Idx: idx, Handle: handle, Format: format, IssuedAt: now, Unchecked: unchecked}
			if err := s.save(); err != nil {
				delete(s.entries, idx)
				return 0, err
			}
			return idx, nil
		}
	}
}

// release frees an index whose credential wasn't issued after all.
func (s *statusList) release(idx int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, idx)
	if err := s.save(); err != nil {
		log.Printf("issuerapp: %v", err)
	}
}

// revoke marks idx's credential revoked; false if no credential has it.
func (s *statusList) revoke(idx int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[idx]
	if !ok {
		return false
	}
	e.Revoked, s.revoked[idx] = true, 1
	if err := s.save(); err != nil {
		log.Printf("issuerapp: %v (the revocation holds until restart)", err)
	}
	return true
}

// revokeHandle revokes the credential whose entry has handle; false if
// none does.
func (s *statusList) revokeHandle(handle string) bool {
	s.mu.Lock()
	idx := -1
	for i, e := range s.entries {
		if handle != "" && e.Handle == handle {
			idx = i
		}
	}
	s.mu.Unlock()
	return idx >= 0 && s.revoke(idx)
}

// newHandle is a random IssuedStatus.Handle.
func newHandle() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// snapshot copies the list's statuses and its entries, newest first.
func (s *statusList) snapshot() ([]uint8, []IssuedStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := make([]IssuedStatus, 0, len(s.entries))
	for _, e := range s.entries {
		entries = append(entries, *e)
	}
	slices.SortFunc(entries, func(a, b IssuedStatus) int { return b.IssuedAt.Compare(a.IssuedAt) })
	return slices.Clone(s.revoked), entries
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
// signed by the document signer with its certificate in the token's
// x5c/x5chain (HAIP 1.0), in the form the Accept header asks for. When
// it names neither, the first serves a JWT (SD-JWT VC requires a JWT
// Status List Token) and the second a CWT (an mdoc's). A token's sub is
// its URI, so each URI has its own Publisher.
func (a *App) statusPublishers() (jwt, cwt *statuslist.Publisher) {
	publisher := func(uri string, form statuslist.Form) *statuslist.Publisher {
		return &statuslist.Publisher{
			URI: uri, Signer: a.documentSigner, Chain: a.documentChain(),
			Statuses: func(context.Context) ([]uint8, error) {
				revoked, _ := a.statusList.snapshot()
				return revoked, nil
			},
			DefaultForm: form,
			Lifetime:    statusTokenLifetime, TTL: statusTokenTTL * time.Second, Now: a.now,
		}
	}
	a.publishers = []*statuslist.Publisher{
		publisher(a.statusListURI, statuslist.FormJWT),
		publisher(a.mdocStatusListURI, statuslist.FormCWT),
	}
	return a.publishers[0], a.publishers[1]
}

var statusTemplate = template.Must(template.New("status").Parse(pageHead + "</head><body>\n" + `
<h1>Issued credentials</h1>
<p>Every credential this issuer has issued references its status list: an SD-JWT VC at <code>{{.URI}}</code>, an mdoc at <code>{{.URI}}/cwt</code>, the same list served as a CWT by default. Revoking one flips its bit; a verifier checking the list then rejects it.</p>
{{if .Entries}}
<table>
<tr><th>Format</th><th>Issued</th><th>Status</th><th></th></tr>
{{range .Entries}}
<tr><td><code>{{.Format}}</code>{{if .Unchecked}} <span class="warn">— issued without Passive Authentication (gmrtd's sample)</span>{{end}}</td><td>{{.IssuedAt.UTC.Format "2006-01-02"}}</td>
<td>{{if .Revoked}}<span class="warn">revoked</span>{{else}}<span class="ok">valid</span>{{end}}</td>
<td>{{if not .Revoked}}<form method="post" action="/demo/status/revoke"><input type="hidden" name="handle" value="{{.Handle}}"><button>Revoke</button></form>{{end}}</td></tr>
{{end}}
</table>
{{else}}
<p>None yet.</p>
{{end}}
<h2>What the wallets reported</h2>
<p>After receiving a credential, the wallet tells this issuer whether it kept it (OID4VCI 1.0 §11, the Notification Endpoint).</p>
{{if .Notifications}}
<table>
<tr><th>Received</th><th>Event</th><th>Description</th></tr>
{{range .Notifications}}
<tr><td>{{.At.Format "15:04:05"}}</td><td><code>{{.Event}}</code></td><td>{{.Description}}</td></tr>
{{end}}
</table>
{{else}}
<p>None yet.</p>
{{end}}
<p class="note">Demo only: anyone who can reach this page can revoke. Entries record no passport data, and don't show the credentials' status list indices. They're kept across restarts only under <code>cmd/demo</code>.</p>
<p><a href="/demo/">Issue another</a> · <a href="/demo/review">Issuances awaiting review</a></p>
` + pageFoot))

// IssuedStatuses lists every credential this issuer has issued, newest
// first, with its status list index and whether it's revoked.
func (a *App) IssuedStatuses() []IssuedStatus {
	_, entries := a.statusList.snapshot()
	return entries
}

func (a *App) handleStatusPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(headerContentType, contentTypeHTML)
	_ = statusTemplate.Execute(w, struct {
		URI           string
		Entries       []IssuedStatus
		Notifications []NotificationEvent
	}{a.statusListURI, a.IssuedStatuses(), a.Notifications()})
}

// handleRevoke revokes one credential. A cross-origin form post is
// refused, so another site can't revoke through a visitor's browser.
func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		a.writeHTMLError(w, http.StatusForbidden, "cross-origin revocation refused")
		return
	}
	if !a.statusList.revokeHandle(r.FormValue("handle")) {
		a.writeHTMLError(w, http.StatusBadRequest, "unknown credential")
		return
	}
	for _, p := range a.publishers {
		p.Invalidate() // serve the revocation at once
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
