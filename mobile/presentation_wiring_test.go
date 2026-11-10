//go:build mobiletest

package mobile

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// candidateView is what a consent screen reads of a credential that
// can answer a request.
type candidateView struct {
	ID              string
	ShownToVerifier *bool `json:"shown_to_verifier"`
	LinkableHere    *bool `json:"linkable_here"`
}

func (c candidateView) is(shown, linkable bool) bool {
	return c.ShownToVerifier != nil && *c.ShownToVerifier == shown && c.LinkableHere != nil && *c.LinkableHere == linkable
}

// A registration that isn't verified carries nothing but its status:
// none of a registration's details, not even an expiry, reach the app
// for it.
func TestPresentation_RegistrationDetailsOnlyWhenVerified(t *testing.T) {
	h := newHarness(t, false)
	h.receive(t)
	other, _ := testcert.CA(t, "another registrar")
	registration := func(w *Wallet, link string) map[string]any {
		t.Helper()
		p, err := w.StartPresentation(NewOperation(0), link)
		if err != nil {
			t.Fatal(err)
		}
		return decode[struct{ Registration map[string]any }](t, p.Verifier()).Registration
	}
	registered := decode[struct{ ID, Link string }](t, mustText(t)(h.env.RegisteredRequest("dc+sd-jwt", "")))
	// registrar_roots that aren't the registrar's: the registration
	// doesn't verify.
	strangers := h.withConfig(t, map[string]any{"registrar_roots": pemOf("CERTIFICATE", other.Raw)})
	if got := registration(strangers.w, registered.Link); len(got) != 1 || got["status"] != "invalid" {
		t.Errorf("an unverified registration = %v, want its status alone, invalid", got)
	}
	plain := decode[struct{ ID, Link string }](t, mustText(t)(h.env.Request("dc+sd-jwt")))
	if got := registration(h.w, plain.Link); len(got) != 1 || got["status"] != "none" {
		t.Errorf("no registration = %v, want its status alone, none", got)
	}
}

// A query naming no claims is flagged in full against the Verifier's
// registration: unregistered_all.
func TestPresentation_UnregisteredAll(t *testing.T) {
	h := newHarness(t, false)
	h.receive(t)
	q, err := h.env.env.SDJWTQuery("pid")
	if err != nil {
		t.Fatal(err)
	}
	_, link, err := h.env.rv.Begin(dcql.Query{Credentials: []dcql.CredentialQuery{q}})
	if err != nil {
		t.Fatal(err)
	}
	p, err := h.w.StartPresentation(NewOperation(0), link)
	if err != nil {
		t.Fatal(err)
	}
	got := decode[struct {
		Registration struct{ Status string }
	}](t, p.Verifier())
	qs := decode[struct {
		Queries []struct {
			UnregisteredAll bool `json:"unregistered_all"`
		}
	}](t, p.Queries())
	if got.Registration.Status != "verified" || len(qs.Queries) != 1 || !qs.Queries[0].UnregisteredAll {
		t.Errorf("a query naming no claims: registration %+v, queries %s; want verified, unregistered_all", got.Registration, p.Queries())
	}
}

// A credential's only copy, presented to one Verifier, is linkable at
// another: Queries says so there, and that it hasn't been shown there.
func TestPresentation_LinkableAtAnotherVerifier(t *testing.T) {
	h := newHarness(t, false)
	var sdjwt string
	for _, c := range h.receive(t) {
		if c.Format == "dc+sd-jwt" {
			sdjwt = c.ID
		}
	}
	candidate := func(link string) (*Presentation, candidateView) {
		t.Helper()
		p, err := h.w.StartPresentation(NewOperation(0), link)
		if err != nil {
			t.Fatal(err)
		}
		q := decode[struct {
			Queries []struct{ Credentials []candidateView }
		}](t, p.Queries())
		if len(q.Queries) != 1 || len(q.Queries[0].Credentials) != 1 {
			t.Fatalf("Queries = %s", p.Queries())
		}
		return p, q.Queries[0].Credentials[0]
	}
	first := decode[struct{ ID, Link string }](t, mustText(t)(h.env.Request("dc+sd-jwt")))
	p, c := candidate(first.Link)
	if !c.is(false, false) {
		t.Errorf("before presenting it: %+v, want not shown, not linkable", c)
	}
	if _, err := p.Respond(NewOperation(0), `{"pid":["`+sdjwt+`"]}`); err != nil {
		t.Fatal(err)
	}
	// The registered Verifier is another one.
	second := decode[struct{ ID, Link string }](t, mustText(t)(h.env.RegisteredRequest("dc+sd-jwt", "")))
	if _, c := candidate(second.Link); !c.is(false, true) {
		t.Errorf("at another Verifier: %+v, want not shown there, linkable", c)
	}
}

// An mdoc presented to the page at one origin is, through the Digital
// Credentials API, shown to that origin and linkable at another: in
// Request and MdocCandidates alike.
func TestMdocPresentation_ShownAndLinkableByOrigin(t *testing.T) {
	const otherOrigin = "https://other-shop.example"
	reader := newTestReader(t)
	h := newHarness(t, false)
	var mdocID string
	for _, c := range h.receive(t) {
		if c.Format == "mso_mdoc" {
			mdocID = c.ID
		}
	}
	requested := func(origin string) (*MdocPresentation, candidateView) {
		t.Helper()
		data, _ := reader.askAt(t, origin)
		p, err := h.w.StartMdocPresentation(NewOperation(0), data, origin)
		if err != nil {
			t.Fatal(err)
		}
		req := decode[struct {
			Documents []struct{ Credentials []candidateView }
		}](t, p.Request())
		if len(req.Documents) != 1 || len(req.Documents[0].Credentials) != 1 {
			t.Fatalf("Request = %s", p.Request())
		}
		return p, req.Documents[0].Credentials[0]
	}
	candidate := func(origin string) candidateView {
		t.Helper()
		cands := decode[struct{ Credentials []candidateView }](t, mustText(t)(h.w.MdocCandidates(origin))).Credentials
		if len(cands) != 1 || cands[0].ID != mdocID {
			t.Fatalf("MdocCandidates(%s) = %+v", origin, cands)
		}
		return cands[0]
	}
	p, _ := requested(readerOrigin)
	if _, err := p.Respond(NewOperation(0), 0, mdocID, `[["`+walletflowtest.NameSpace+`","family_name"]]`); err != nil {
		t.Fatal(err)
	}
	if _, c := requested(readerOrigin); !c.is(true, false) {
		t.Errorf("Request at the origin it was shown to: %+v, want shown, not linkable", c)
	}
	if _, c := requested(otherOrigin); !c.is(false, true) {
		t.Errorf("Request at another origin: %+v, want not shown, linkable", c)
	}
	if c := candidate(otherOrigin); !c.is(false, true) {
		t.Errorf("MdocCandidates at another origin: %+v, want not shown, linkable", c)
	}
	if c := candidate(readerOrigin); !c.is(true, false) {
		t.Errorf("MdocCandidates at the origin it was shown to: %+v, want shown, not linkable", c)
	}
}

// A reader whose certificate doesn't chain to mdoc_reader_roots is
// "untrusted", and the name its certificate gives is only claimed: the
// holder isn't shown it as the reader's.
func TestSessions_ProximityUntrustedReaderHasNoName(t *testing.T) {
	reader, recognized := newTestReader(t), newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, recognized)
	h.receive(t)
	p, _, msg := startProximity(t, h, &reader)
	if ev := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), msg)); ev.Event != "request" {
		t.Fatalf("HandleMessage = %+v", ev)
	}
	var got struct {
		Reader struct {
			Status, Name string
			ClaimedName  string `json:"claimed_name"`
		}
	}
	if err := json.Unmarshal([]byte(p.Request()), &got); err != nil {
		t.Fatal(err)
	}
	if got.Reader.Status != "untrusted" || got.Reader.Name != "" || got.Reader.ClaimedName != "Test Shop" {
		t.Errorf("reader = %+v, want untrusted, no name, claimed name Test Shop", got.Reader)
	}
}
