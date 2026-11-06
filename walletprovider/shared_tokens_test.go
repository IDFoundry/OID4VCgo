package walletprovider_test

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/statuslist/statuslisttest"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// TestStatusListsSharedTokens: two providers over one set of stores,
// sharing a TokenStore, serve the one token either signs, and a
// revocation through one is served by the other from its next check.
func TestStatusListsSharedTokens(t *testing.T) {
	tokens := statuslisttest.NewMemoryTokenStore()
	a := newHarness(t, func(_ *walletprovider.Config, d *walletprovider.Dependencies) { d.StatusListTokens = tokens })
	pb, err := walletprovider.New(a.cfg, a.deps)
	if err != nil {
		t.Fatal(err)
	}
	b := &harness{t: t, p: pb, clock: a.clock, signer: a.signer, chain: a.chain, cfg: a.cfg, deps: a.deps}

	in, _ := a.register(kindStrongBox)
	key := a.newInstanceKey(in.ID, kindStrongBox)
	ref := a.instanceKey(&key.PublicKey).Status
	path := strings.TrimPrefix(ref.URI, statusBase)
	codeA, tokenA := a.getStatusList(path, statuslist.TokenMediaType)
	codeB, tokenB := b.getStatusList(path, statuslist.TokenMediaType)
	if codeA != http.StatusOK || codeB != http.StatusOK {
		t.Fatalf("GET %s: %d and %d", path, codeA, codeB)
	}
	if !bytes.Equal(tokenA, tokenB) {
		t.Fatal("the providers serve different tokens: each signed its own")
	}
	if got := b.status(ref, false); got != statuslist.StatusValid {
		t.Fatalf("status before the revocation = %v, want VALID", got)
	}

	if err := a.p.Revoke(context.Background(), in.ID, "compromised"); err != nil {
		t.Fatal(err)
	}
	// The list's version rises with the status change, as sqlstore's
	// does in the same transaction; this store's rises only when told.
	tokens.Bump(ref.URI)
	if got := a.status(ref, false); got != statuslist.StatusInvalid {
		t.Fatalf("status the revoking provider serves = %v, want INVALID", got)
	}
	a.clock.advance(statuslist.DefaultTokensCheck + time.Second)
	if got := b.status(ref, false); got != statuslist.StatusInvalid {
		t.Fatalf("status the other provider serves after its next check = %v, want INVALID", got)
	}
	_, tokenA = a.getStatusList(path, statuslist.TokenMediaType)
	_, tokenB = b.getStatusList(path, statuslist.TokenMediaType)
	if !bytes.Equal(tokenA, tokenB) {
		t.Fatal("after the revocation, the providers serve different tokens")
	}
}
