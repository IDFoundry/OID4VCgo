package walletflow_test

import (
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/wallet"
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
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	if len(c.Copies) != 3 || c.CopiesLeft() != 3 || f.keys.Len() != 3 {
		t.Fatalf("copies = %d (%d left), keys = %d; want 3 of each", len(c.Copies), c.CopiesLeft(), f.keys.Len())
	}
	assertDistinct(t, c.Copies)

	presented := map[string]bool{}
	for i := range 4 {
		stored := presentOnce(t, f, v, w, c.ID)
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

	ctx := context.Background()
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

// assertDistinct checks no two copies share a key or a credential.
func assertDistinct(t *testing.T, copies []walletflow.CredentialCopy) {
	t.Helper()
	seen := map[string]bool{}
	for _, cp := range copies {
		if seen[cp.HolderKeyID] || seen[cp.Credential] {
			t.Fatal("two copies share a key or a credential")
		}
		seen[cp.HolderKeyID], seen[cp.Credential] = true, true
	}
}

// presentOnce answers a fresh request for the SD-JWT VC and returns the
// stored credential id names afterwards.
func presentOnce(t *testing.T, f fixture, v testVerifier, w *walletflow.Wallet, id string) walletflow.StoredCredential {
	t.Helper()
	ctx := context.Background()
	txID, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Respond(ctx, walletflow.Selection{"pid": {id}}); err != nil {
		t.Fatal(err)
	}
	if view := v.Lookup(t, txID); len(view.Result.Credentials) != 1 {
		t.Fatalf("verifier = %+v", view)
	}
	stored, err := f.store.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return stored
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

// Two presentations open at once each present a copy the other doesn't:
// copies are chosen from the store when answering, not when the request
// arrived. A response refused before it's sent leaves its copy unused.
func TestBatch_ConcurrentPresentationsUseDistinctCopies(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	v := f.env.StartVerifier(t)
	w := f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	ctx := context.Background()
	start := func() *walletflow.Presentation {
		_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
		p, err := w.StartPresentation(ctx, link)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p1, p2 := start(), start()
	if _, err := p2.Respond(ctx, walletflow.Selection{"pid": {c.ID, c.ID}}); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Fatalf("Respond with the credential twice = %v, want ErrInvalidSelection", err)
	}
	// Refused after its copy was reserved: the copy is released.
	if _, err := p2.Respond(ctx, walletflow.Selection{"other": {c.ID}}); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Fatalf("Respond for an unknown query = %v, want ErrInvalidSelection", err)
	}
	if kept, _ := w.Credentials(ctx); len(kept) != 1 || kept[0].CopiesLeft() != 3 {
		t.Fatalf("after a refused response: %+v; want every copy unused", kept)
	}
	for _, p := range []*walletflow.Presentation{p1, p2} {
		if _, err := p.Respond(ctx, walletflow.Selection{"pid": {c.ID}}); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := w.Credentials(ctx)
	if err != nil || len(stored) != 1 {
		t.Fatal(stored, err)
	}
	presented := 0
	for _, cp := range stored[0].Copies {
		if cp.Presented {
			presented++
		}
	}
	if presented != 2 || stored[0].CopiesLeft() != 1 {
		t.Errorf("%d copies presented, %d left; want 2 distinct presented and 1 left", presented, stored[0].CopiesLeft())
	}
}

// twoVerifiersWallet is a wallet, with copyPolicy, trusting two
// Verifiers with different client_ids.
func twoVerifiersWallet(t *testing.T, f fixture, policy walletflow.CopyPolicy) (*walletflow.Wallet, testVerifier, testVerifier) {
	t.Helper()
	v1, v2 := f.env.StartVerifier(t), f.env.StartVerifier(t)
	roots := x509.NewCertPool()
	roots.AddCert(v1.CA)
	roots.AddCert(v2.CA)
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		VerifierTrust: wallet.X5CVerifierRoots{Roots: roots}, Development: true, CopyPolicy: policy,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	return w, v1, v2
}

// Per presentation, every presentation uses a new copy, even to the same
// Verifier; per Verifier, a Verifier sees the same copy each time, and
// another Verifier a different one. Either way, each copy records which
// Verifiers saw it.
func TestCopyPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy           walletflow.CopyPolicy
		leftAfterSameTwo int
		leftAfterOther   int
	}{
		{walletflow.CopyPerPresentation, 1, 0},
		{walletflow.CopyPerVerifier, 2, 1},
	} {
		f := newFixture(t, walletflowtest.Options{BatchSize: 3})
		w, v1, v2 := twoVerifiersWallet(t, f, tc.policy)
		c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
		presentOnce(t, f, v1, w, c.ID)
		second := presentOnce(t, f, v1, w, c.ID)
		if second.CopiesLeft() != tc.leftAfterSameTwo {
			t.Errorf("policy %d: after two presentations to one Verifier, %d copies left, want %d", tc.policy, second.CopiesLeft(), tc.leftAfterSameTwo)
		}
		if !second.ShownTo(v1.ClientID) || second.ShownTo(v2.ClientID) {
			t.Errorf("policy %d: ShownTo v1 %v, v2 %v; want v1 only", tc.policy, second.ShownTo(v1.ClientID), second.ShownTo(v2.ClientID))
		}
		other := presentOnce(t, f, v2, w, c.ID)
		if other.CopiesLeft() != tc.leftAfterOther || !other.ShownTo(v2.ClientID) {
			t.Errorf("policy %d: after another Verifier, %d copies left (want %d), ShownTo v2 %v", tc.policy, other.CopiesLeft(), tc.leftAfterOther, other.ShownTo(v2.ClientID))
		}
		// The second Verifier never saw the first's copy.
		for _, cp := range other.Copies {
			if slices.Contains(cp.ShownTo, walletflow.VerifierHash(v1.ClientID)) && slices.Contains(cp.ShownTo, walletflow.VerifierHash(v2.ClientID)) {
				t.Errorf("policy %d: one copy was shown to both Verifiers", tc.policy)
			}
		}
	}
}

// Per Verifier, a response refused before it's sent leaves a reused
// copy as it was: still presented, still shown to that Verifier.
func TestCopyPolicy_PerVerifierReleaseKeepsAReusedCopy(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	w, v1, _ := twoVerifiersWallet(t, f, walletflow.CopyPerVerifier)
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	presentOnce(t, f, v1, w, c.ID)
	ctx := context.Background()
	_, link := v1.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Respond(ctx, walletflow.Selection{"other": {c.ID}}); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Fatalf("Respond for an unknown query = %v, want ErrInvalidSelection", err)
	}
	kept, _ := w.Credentials(ctx)
	if len(kept) != 1 || kept[0].CopiesLeft() != 2 || !kept[0].ShownTo(v1.ClientID) {
		t.Errorf("after a refused response: %d left, ShownTo %v; want the reused copy kept as it was", kept[0].CopiesLeft(), kept[0].ShownTo(v1.ClientID))
	}
}

// Once every copy has been presented, the copy shown to the fewest
// Verifiers is reused, spreading Verifiers across copies rather than
// piling them all onto one.
func TestCopyPolicy_ReusesTheLeastShownCopy(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 2})
	vs := make([]testVerifier, 4)
	roots := x509.NewCertPool()
	for i := range vs {
		vs[i] = f.env.StartVerifier(t)
		roots.AddCert(vs[i].CA)
	}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		VerifierTrust: wallet.X5CVerifierRoots{Roots: roots}, Development: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	var last walletflow.StoredCredential
	for _, v := range vs {
		last = presentOnce(t, f, v, w, c.ID)
	}
	if n0, n1 := len(last.Copies[0].ShownTo), len(last.Copies[1].ShownTo); n0 != 2 || n1 != 2 {
		t.Errorf("four Verifiers across two copies: shown to %d and %d, want 2 and 2", n0, n1)
	}
}
