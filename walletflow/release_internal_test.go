package walletflow

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
)

// A presentation that isn't sent leaves its copy marked when another
// presentation to the same Verifier reserved that copy after it: that
// one may have been sent, and undoing what it recorded would hand the
// copy to the next Verifier as one no Verifier has seen — whether the
// later one was reserved by the same Wallet or by another sharing the
// store (another process).
func TestRelease_KeepsALaterReservation(t *testing.T) {
	never := func(string) bool { return false }
	for name, tc := range map[string]struct {
		policy      CopyPolicy
		cred        StoredCredential
		otherWallet bool
	}{
		"per Verifier, reusing the copy": {policy: CopyPerVerifier, cred: StoredCredential{ID: "pid", Copies: []CredentialCopy{
			{Credential: "copy0", HolderKeyID: "k0"}, {Credential: "copy1", HolderKeyID: "k1"},
		}}},
		"per presentation, one copy": {policy: CopyPerPresentation, cred: StoredCredential{ID: "pid", Credential: "only", HolderKeyID: "k0"}},
		"per presentation, one copy, another Wallet": {
			policy: CopyPerPresentation, cred: StoredCredential{ID: "pid", Credential: "only", HolderKeyID: "k0"}, otherWallet: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := NewMemoryCredentialStore()
			w := &Wallet{cfg: Config{CopyPolicy: tc.policy}, deps: Dependencies{Credentials: store, Clock: time.Now, Random: rand.Reader}}
			other := w
			if tc.otherWallet {
				other = &Wallet{cfg: w.cfg, deps: w.deps}
			}
			if err := store.Put(ctx, tc.cred); err != nil {
				t.Fatal(err)
			}
			shown := map[string]StoredCredential{"pid": tc.cred}
			v := VerifierHash("https://v.example")
			a, err := w.reserve(ctx, Selection{"q": {"pid"}}, v, never, shown)
			if err != nil {
				t.Fatal(err)
			}
			b, err := other.reserve(ctx, Selection{"q": {"pid"}}, v, never, shown)
			if err != nil {
				t.Fatal(err)
			}
			if a[0].keyID != b[0].keyID {
				t.Fatalf("the two presentations reserved %q and %q, want one copy", a[0].keyID, b[0].keyID)
			}
			// b is sent; a fails before sending.
			w.release(ctx, a, v)

			got, err := store.Get(ctx, "pid")
			if err != nil {
				t.Fatal(err)
			}
			cp := got.AllCopies()[0]
			if !cp.Presented || !got.ShownTo("https://v.example") {
				t.Errorf("after a's release the copy b presented records Presented=%v ShownTo=%v", cp.Presented, cp.ShownTo)
			}
			v3 := VerifierHash("https://v3.example")
			if _, next, _ := got.copyFor(tc.policy, v3, time.Now()); next.HolderKeyID == b[0].keyID && !w.linkable(got, v3) {
				t.Error("the next Verifier would be given the copy v holds, unwarned")
			}
		})
	}
}

// With no reservation since, release undoes what reserve recorded.
func TestRelease_UndoesTheLatestReservation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStore()
	w := &Wallet{deps: Dependencies{Credentials: store, Clock: time.Now, Random: rand.Reader}}
	c := StoredCredential{ID: "pid", Credential: "only", HolderKeyID: "k0"}
	if err := store.Put(ctx, c); err != nil {
		t.Fatal(err)
	}
	v := VerifierHash("https://v.example")
	a, err := w.reserve(ctx, Selection{"q": {"pid"}}, v, func(string) bool { return false }, map[string]StoredCredential{"pid": c})
	if err != nil {
		t.Fatal(err)
	}
	w.release(ctx, a, v)
	got, err := store.Get(ctx, "pid")
	if err != nil {
		t.Fatal(err)
	}
	if cp := got.AllCopies()[0]; cp.Presented || len(cp.ShownTo) != 0 {
		t.Errorf("after release the copy records Presented=%v ShownTo=%v, want neither", cp.Presented, cp.ShownTo)
	}
}
