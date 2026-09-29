package issuerapp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListPath is where this issuer serves its one Token Status List,
// which every credential it issues references for revocation.
const StatusListPath = "/statuslists/1"

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
	Handle   string
	Format   string
	IssuedAt time.Time
	Revoked  bool
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

// allocate reserves a random unused index for a credential of format.
func (s *statusList) allocate(format string, now time.Time) (int, error) {
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
			s.entries[idx] = &IssuedStatus{Idx: idx, Handle: handle, Format: format, IssuedAt: now}
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
// status list.
func (a *App) withStatus(c *issuer.CredentialInstance, idx int) {
	if c.SDJWTClaims != nil {
		c.SDJWTClaims.Status = statuslist.StatusListRef{Idx: idx, URI: a.statusListURI}.Claim()
	}
	if c.MdocClaims != nil {
		c.MdocClaims.Status = &mdoc.StatusListRef{Idx: uint64(idx), URI: a.statusListURI} // #nosec G115 -- idx is from allocate, in [0, statusListSize)
	}
}

// handleStatusList serves the Status List Token, signed by the document
// signer with its certificate in the token's x5c (HAIP 1.0), in the
// format the Accept header asks for: CWT for an mdoc's reference, JWT
// otherwise (SD-JWT VC requires a JWT Status List Token).
func (a *App) handleStatusList(w http.ResponseWriter, r *http.Request) {
	revoked, _ := a.statusList.snapshot()
	sl, err := statuslist.New(statuslist.Bits1, revoked, "")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := a.now()
	exp, ttl := now.Add(statusTokenLifetime).Unix(), int64(statusTokenTTL)
	claims := statuslist.TokenClaims{Sub: a.statusListURI, Iat: now.Unix(), Exp: &exp, TTL: &ttl, StatusList: sl}
	w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(statusTokenTTL))
	if strings.Contains(r.Header.Get("Accept"), statuslist.CWTTokenMediaType) {
		token, err := statuslist.IssueTokenCWTX5Chain(a.documentSigner, cose.ES256, claims, a.documentChain())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(token)
		return
	}
	token, err := statuslist.IssueTokenX5C(a.documentSigner, jose.ES256, claims, a.documentChain())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", statuslist.TokenMediaType)
	_, _ = w.Write([]byte(token))
}

var statusTemplate = template.Must(template.New("status").Parse(pageHead + `
<h1>Issued credentials</h1>
<p>Every credential this issuer has issued references its status list at <code>{{.URI}}</code>. Revoking one flips its bit; a verifier checking the list then rejects it.</p>
{{if .Entries}}
<table>
<tr><th>Format</th><th>Issued</th><th>Status</th><th></th></tr>
{{range .Entries}}
<tr><td><code>{{.Format}}</code></td><td>{{.IssuedAt.Format "15:04:05"}}</td>
<td>{{if .Revoked}}<span class="warn">revoked</span>{{else}}<span class="ok">valid</span>{{end}}</td>
<td>{{if not .Revoked}}<form method="post" action="/status/revoke"><input type="hidden" name="handle" value="{{.Handle}}"><button>Revoke</button></form>{{end}}</td></tr>
{{end}}
</table>
{{else}}
<p>None yet.</p>
{{end}}
<p class="note">Demo only: anyone who can reach this page can revoke. Entries record no passport data, and don't show the credentials' status list indices. They're kept across restarts only under <code>cmd/demo</code>.</p>
<p><a href="/">Issue another</a></p>
` + pageFoot))

// IssuedStatuses lists every credential this issuer has issued, newest
// first, with its status list index and whether it's revoked.
func (a *App) IssuedStatuses() []IssuedStatus {
	_, entries := a.statusList.snapshot()
	return entries
}

func (a *App) handleStatusPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = statusTemplate.Execute(w, struct {
		URI     string
		Entries []IssuedStatus
	}{a.statusListURI, a.IssuedStatuses()})
}

// handleRevoke revokes one credential. A cross-origin form post is
// refused, so another site can't revoke through a visitor's browser.
func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		writeHTMLError(w, http.StatusForbidden, "cross-origin revocation refused")
		return
	}
	if !a.statusList.revokeHandle(r.FormValue("handle")) {
		writeHTMLError(w, http.StatusBadRequest, "unknown credential")
		return
	}
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

// credentialFormat is the format of credential configuration id.
func credentialFormat(id string) string {
	if id == MdocConfigurationID {
		return mdoc.CredentialFormat
	}
	return sdjwtvc.CredentialFormat
}
