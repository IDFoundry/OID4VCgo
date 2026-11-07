package statuslist_test

import (
	"context"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// An issuer handing out random, never-reused status list indices, and
// publishing the list they're in. A credential issued as a batch of
// copies takes one index per copy, so Relying Parties can't link the
// copies by their status entry; revoking the credential revokes every
// copy.
func ExampleAllocator() {
	ctx := context.Background()
	const uri = "https://issuer.example/statuslists/1"
	alloc := &statuslist.Allocator{
		Lists: []statuslist.AllocatorList{{URI: uri, Size: 1 << 16}},
		// A durable, shared IndexStore in production: a restart must
		// not forget which indices are taken.
		Store: &statuslist.MemoryIndexStore{},
	}
	signer, chain := statusListSigner()
	list := &statuslist.Publisher{URI: uri, Signer: signer, Chain: chain, Statuses: alloc.Statuses(uri)}

	// At issuance: one index per copy, each embedded in its copy's
	// status claim (ref.Claim(), or ref.CWTStatusClaim() for an mdoc).
	copies := make([]statuslist.StatusListRef, 3)
	for i := range copies {
		copies[i] = must(alloc.Allocate(ctx))
	}

	// Revoking the credential: every copy, then serve the change at once.
	for _, ref := range copies {
		if err := alloc.SetStatus(ctx, ref, statuslist.StatusInvalid); err != nil {
			panic(err)
		}
	}
	list.Invalidate()

	// A Relying Party reading the published list.
	token := must(list.Token(ctx, false))
	for _, ref := range copies {
		status, _, err := statuslist.Check(string(token), &signer.PublicKey, oid4vci.ES256, ref,
			statuslist.VerifyOptions{UnboundSigner: statuslist.AnyListSigner})
		if err != nil {
			panic(err)
		}
		fmt.Println(status)
	}

	// Output:
	// INVALID
	// INVALID
	// INVALID
}

// Watching how full an Allocator's lists are, from monitoring: once the
// lists still taking indices run low, provision another list and append
// it to Lists, before Allocate fails with ErrListsFull.
func ExampleAllocator_Fill() {
	ctx := context.Background()
	alloc := &statuslist.Allocator{
		Lists: []statuslist.AllocatorList{
			{URI: "https://issuer.example/statuslists/1", Size: 64},
			{URI: "https://issuer.example/statuslists/2", Size: 64},
		},
		Store: &statuslist.MemoryIndexStore{},
	}
	for range 40 {
		must(alloc.Allocate(ctx))
	}

	free := 0
	for _, list := range must(alloc.Fill(ctx)) {
		fmt.Printf("%s: %d of %d reserved, full: %v\n", list.URI, list.Reserved, list.Limit, list.Full())
		free += list.Free()
	}
	fmt.Println("free:", free)

	// Output:
	// https://issuer.example/statuslists/1: 32 of 32 reserved, full: true
	// https://issuer.example/statuslists/2: 8 of 32 reserved, full: false
	// free: 24
}
