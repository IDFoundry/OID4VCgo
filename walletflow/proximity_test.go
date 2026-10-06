package walletflow_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// proximityRequest has a reader scan p's QR code and send its request
// for family_name and given_name, signed with reader's key if reader
// isn't nil.
func proximityRequest(t *testing.T, p *walletflow.ProximityPresentation, reader *mdocReader) (*proximity.ReaderSession, []byte) {
	t.Helper()
	var opts []proximity.ReaderOption
	if reader != nil {
		opts = append(opts, proximity.WithReaderAuth(reader.key.Signer, reader.key.Chain))
	}
	r, err := proximity.NewReaderSession(p.QRCode(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	if r.ServiceUUID() != p.ServiceUUID() {
		t.Fatalf("reader UUID %s, holder %s", r.ServiceUUID(), p.ServiceUUID())
	}
	msg, err := r.Establishment(walletflowtest.DocType, map[string][]string{walletflowtest.NameSpace: {"family_name", "given_name"}})
	if err != nil {
		t.Fatal(err)
	}
	return r, msg
}

func heldMdoc(t *testing.T, held []walletflow.StoredCredential) string {
	t.Helper()
	for _, c := range held {
		if c.Format == "mso_mdoc" {
			return c.ID
		}
	}
	t.Fatal("no mdoc held")
	return ""
}

func TestProximityPresentation(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	reader := newMdocReader(t)
	w := mdocWallet(t, f, reader.roots, walletflow.CopyPerPresentation)
	mdocID := heldMdoc(t, receive(t, f, w, walletflowtest.MdocConfigurationID))
	ctx := context.Background()

	p, err := w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	r, msg := proximityRequest(t, p, &reader)
	ev := p.HandleMessage(ctx, msg)
	if !ev.Request || ev.Ended || ev.Send != nil || ev.Err != nil {
		t.Fatalf("event %+v", ev)
	}
	if got := p.Reader(); got.Status != proximity.ReaderTrusted || !got.Chain[0].Equal(reader.key.Chain[0]) {
		t.Errorf("Reader = %v (%v)", got.Status, got.Err)
	}
	requests := p.Requests()
	// In the request's order: proximity's reader encodes them sorted.
	want := []walletflow.MdocElement{{Namespace: walletflowtest.NameSpace, Identifier: "given_name"}, {Namespace: walletflowtest.NameSpace, Identifier: "family_name"}}
	if len(requests) != 1 || len(requests[0].Elements) != 2 || requests[0].Elements[0] != want[0] || requests[0].Elements[1] != want[1] {
		t.Fatalf("Requests = %d, elements %+v", len(requests), requests[0].Elements)
	}
	if len(requests[0].Credentials) != 1 || requests[0].Credentials[0].ID != mdocID {
		t.Fatalf("%d credentials, want %s", len(requests[0].Credentials), mdocID)
	}
	if p.Linkable(mdocID) {
		t.Error("an unused copy is linkable")
	}
	if _, err := p.Respond(ctx, 0, mdocID, [][2]string{{walletflowtest.NameSpace, "birth_date"}}); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Errorf("an unrequested element: %v", err)
	}
	if _, err := p.Respond(ctx, 1, mdocID, familyName()); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Errorf("no request 1: %v", err)
	}

	presented, err := p.Respond(ctx, 0, mdocID, familyName())
	if err != nil {
		t.Fatal(err)
	}
	v, err := r.Verify(presented.Send, f.env.IssuerRoots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if v.Claims[walletflowtest.NameSpace]["family_name"] != walletflowtest.FamilyName || len(v.Claims[walletflowtest.NameSpace]) != 1 {
		t.Errorf("disclosed %v, want only family_name", v.Claims)
	}
	if _, err := p.Respond(ctx, 0, mdocID, familyName()); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("a second Respond: %v", err)
	}
	if ev := p.HandleMessage(ctx, msg); !ev.Ended || ev.Err == nil {
		t.Errorf("a message after the response: %+v", ev)
	}

	// The same reader again is known by its certificate; an unsigned
	// one never is.
	again, err := w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	if _, msg := proximityRequest(t, again, &reader); !again.HandleMessage(ctx, msg).Request {
		t.Fatal("no request")
	}
	if !again.ShownTo(mdocID) {
		t.Error("ShownTo is false for the reader it was shown to")
	}
	anon, err := w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	if _, msg := proximityRequest(t, anon, nil); !anon.HandleMessage(ctx, msg).Request {
		t.Fatal("no request")
	}
	if anon.ShownTo(mdocID) {
		t.Error("ShownTo is true for an unsigned reader")
	}
}

// An unsigned request is shown as unauthenticated, unless the wallet
// requires a trusted reader: then the session ends before the holder
// sees it.
func TestProximityPresentationReaderTrust(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	reader := newMdocReader(t)
	other := newMdocReader(t)
	ctx := context.Background()

	for name, tc := range map[string]struct {
		require bool
		signer  *mdocReader
		want    proximity.ReaderStatus
		refused bool
	}{
		"unsigned":                 {false, nil, proximity.ReaderUnauthenticated, false},
		"another CA":               {false, &other, proximity.ReaderUntrusted, false},
		"unsigned, trust required": {true, nil, proximity.ReaderUnauthenticated, true},
		"another CA, required":     {true, &other, proximity.ReaderUntrusted, true},
		"trusted, required":        {true, &reader, proximity.ReaderTrusted, false},
	} {
		t.Run(name, func(t *testing.T) {
			w, err := walletflow.New(walletflow.Config{
				ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
				MdocReaderRoots: reader.roots, RequireTrustedMdocReader: tc.require, Development: true,
			}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
			if err != nil {
				t.Fatal(err)
			}
			p, err := w.StartProximityPresentation()
			if err != nil {
				t.Fatal(err)
			}
			r, msg := proximityRequest(t, p, tc.signer)
			ev := p.HandleMessage(ctx, msg)
			if tc.refused {
				if !ev.Ended || !errors.Is(ev.Err, walletflow.ErrUntrustedVerifier) || ev.Send == nil {
					t.Fatalf("event %+v", ev)
				}
				if _, err := r.Verify(ev.Send, x509.NewCertPool(), time.Now()); !errors.Is(err, proximity.ErrDeclined) {
					t.Errorf("reader: %v, want declined", err)
				}
				return
			}
			if !ev.Request {
				t.Fatalf("event %+v", ev)
			}
			if got := p.Reader().Status; got != tc.want {
				t.Errorf("Reader = %v, want %v", got, tc.want)
			}
		})
	}
}

// The holder declines; the reader ends the session first; or the
// reader's message isn't one: each ends the session.
func TestProximityPresentationEnds(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	reader := newMdocReader(t)
	w := mdocWallet(t, f, reader.roots, walletflow.CopyPerPresentation)
	mdocID := heldMdoc(t, receive(t, f, w, walletflowtest.MdocConfigurationID))
	ctx := context.Background()
	start := func(t *testing.T) (*walletflow.ProximityPresentation, *proximity.ReaderSession) {
		t.Helper()
		p, err := w.StartProximityPresentation()
		if err != nil {
			t.Fatal(err)
		}
		r, msg := proximityRequest(t, p, &reader)
		if ev := p.HandleMessage(ctx, msg); !ev.Request {
			t.Fatalf("event %+v", ev)
		}
		return p, r
	}

	t.Run("declined", func(t *testing.T) {
		p, r := start(t)
		if _, err := r.Verify(p.Terminate(), f.env.IssuerRoots, time.Now()); !errors.Is(err, proximity.ErrDeclined) {
			t.Errorf("reader: %v, want declined", err)
		}
		if _, err := p.Respond(ctx, 0, mdocID, familyName()); !errors.Is(err, walletflow.ErrWrongStep) {
			t.Errorf("Respond after Terminate: %v", err)
		}
	})
	t.Run("reader ended", func(t *testing.T) {
		p, r := start(t)
		ev := p.HandleMessage(ctx, r.Termination())
		if !ev.Ended || !errors.Is(ev.Err, walletflow.ErrReaderEnded) || ev.Send != nil {
			t.Errorf("event %+v", ev)
		}
	})
	t.Run("a second request", func(t *testing.T) {
		p, _ := start(t)
		// Not encrypted for this session: a session encryption error.
		ev := p.HandleMessage(ctx, []byte{0xa1, 0x64, 'd', 'a', 't', 'a', 0x41, 0x00})
		if !ev.Ended || ev.Err == nil || ev.Send == nil {
			t.Errorf("event %+v", ev)
		}
	})
	t.Run("not a SessionEstablishment", func(t *testing.T) {
		p, err := w.StartProximityPresentation()
		if err != nil {
			t.Fatal(err)
		}
		ev := p.HandleMessage(ctx, []byte{0x01})
		if !ev.Ended || !errors.Is(ev.Err, proximity.ErrCBORDecoding) {
			t.Fatalf("event %+v", ev)
		}
		if status, _ := proximity.StatusFor(proximity.ErrCBORDecoding); string(ev.Send) != string(proximity.StatusMessage(status)) {
			t.Errorf("Send = %x", ev.Send)
		}
	})
}
