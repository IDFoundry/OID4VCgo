package walletflow_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// An issuer offering batches issues the wallet several copies of a
// credential, each bound to its own key; each presentation uses a copy
// no Verifier has seen, until none is left.
func TestBatch(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	v := f.env.StartVerifier(t)
	w := f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	c := held[0]
	if len(c.Copies) != 3 || c.CopiesLeft() != 3 || f.keys.Len() != 3 {
		t.Fatalf("copies = %d (%d left), keys = %d; want 3 of each", len(c.Copies), c.CopiesLeft(), f.keys.Len())
	}
	seen := map[string]bool{}
	for _, cp := range c.Copies {
		if seen[cp.HolderKeyID] || seen[cp.Credential] {
			t.Fatal("two copies share a key or a credential")
		}
		seen[cp.HolderKeyID], seen[cp.Credential] = true, true
	}

	ctx := context.Background()
	presented := map[string]bool{}
	for i := range 4 {
		id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
		p, err := w.StartPresentation(ctx, link)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.Respond(ctx, nil); err != nil {
			t.Fatalf("presentation %d: %v", i, err)
		}
		view := v.Lookup(t, id)
		if len(view.Result.Credentials) != 1 {
			t.Fatalf("presentation %d: verifier = %+v", i, view)
		}
		stored, err := f.store.Get(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		if want := max(0, 2-i); stored.CopiesLeft() != want {
			t.Errorf("after presentation %d: %d copies left, want %d", i, stored.CopiesLeft(), want)
		}
		if k := presentedCopy(stored, presented); k != "" {
			presented[k] = true
		}
	}
	// Three presentations used the three copies; the fourth reused one.
	if len(presented) != 3 {
		t.Errorf("presentations used %d distinct copies, want all 3", len(presented))
	}

	if inUse, err := w.KeysInUse(ctx); err != nil || len(inUse) != 3 {
		t.Errorf("KeysInUse = %v, %v; want every copy's key", inUse, err)
	}
	if err := w.DeleteCredential(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if f.keys.Len() != 0 {
		t.Errorf("keys held after deleting = %d, want none", f.keys.Len())
	}
}

// presentedCopy is the key of a copy stored marks presented that isn't
// in seen yet, or "" — so each presentation's copy can be counted.
func presentedCopy(stored walletflow.StoredCredential, seen map[string]bool) string {
	for _, cp := range stored.Copies {
		if cp.Presented && !seen[cp.HolderKeyID] {
			return cp.HolderKeyID
		}
	}
	return ""
}

// Config.BatchSize caps the copies requested; 1 requests one.
func TestBatch_Size(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 5})
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		Development: true, BatchSize: 1,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	held := receive(t, f, w, walletflowtest.MdocConfigurationID)
	if len(held[0].Copies) != 1 || f.keys.Len() != 1 {
		t.Errorf("copies = %d, keys = %d; want 1", len(held[0].Copies), f.keys.Len())
	}
}

// A deferred batch keeps every copy's key until it's issued.
func TestBatch_Deferred(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3, Defer: true})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.MdocConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Deferred) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if inUse, _ := f.w.KeysInUse(ctx); len(inUse) != 4 {
		t.Errorf("keys in use while deferred = %d, want 3 holder keys and the DPoP key", len(inUse))
	}
	f.env.Decide(true)
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stored, err := result.Deferred[0].Wait(waitCtx)
	if err != nil || len(stored.Copies) != 3 {
		t.Fatalf("Wait = %d copies, %v", len(stored.Copies), err)
	}
	if f.keys.Len() != 3 {
		t.Errorf("keys held = %d, want the 3 copies' keys", f.keys.Len())
	}
}
