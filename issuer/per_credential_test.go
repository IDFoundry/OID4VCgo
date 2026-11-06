package issuer_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// A PerCredential that drops a Credential's claims fails the request,
// rather than panicking after the c_nonce is spent.
func TestRequestCredential_PerCredentialRemovingClaims(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		SDJWTClaims:               testSDJWTClaims(),
		PerCredential: func(_ context.Context, c *issuer.CredentialInstance) error {
			c.SDJWTClaims = nil
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("RequestCredential = %v, want the removed claims refused", err)
	}
}

// PerBatch sees the whole batch once, after PerCredential, and can set
// each Credential's status reference from one AllocateN; the checks
// that follow PerCredential follow it too.
func TestRequestCredential_PerBatch(t *testing.T) {
	ctx := context.Background()
	t.Run("status from AllocateN", func(t *testing.T) {
		f := newCredentialEndpointFixture(t)
		req, keys := batchRequest(t, f)
		alloc := &statuslist.Allocator{Lists: []statuslist.AllocatorList{{URI: "https://issuer.example.com/statuslists/1", Size: 1024}}, Store: &statuslist.MemoryIndexStore{}}
		var order []string
		req.PerCredential = func(_ context.Context, c *issuer.CredentialInstance) error {
			order = append(order, "credential")
			return nil
		}
		req.PerBatch = func(ctx context.Context, batch []*issuer.CredentialInstance) error {
			order = append(order, "batch")
			if len(batch) != len(keys) {
				t.Errorf("PerBatch saw %d Credentials, want %d", len(batch), len(keys))
			}
			refs, err := alloc.AllocateN(ctx, len(batch))
			if err != nil {
				return err
			}
			for i, c := range batch {
				if c.Index != i || !keys[i].Equal(c.BindingKey) {
					t.Errorf("batch[%d] is Credential %d, or not bound to the %d-th proof's key", i, c.Index, i)
				}
				c.SDJWTClaims.Status = refs[i].Claim()
			}
			return nil
		}
		resp, err := f.iss.RequestCredential(ctx, batchAuth, req)
		if err != nil {
			t.Fatalf("RequestCredential: %v", err)
		}
		if !slices.Equal(order, []string{"credential", "credential", "batch"}) {
			t.Errorf("hooks ran %v", order)
		}
		if len(resp.Credentials) != len(keys) {
			t.Fatalf("%d Credentials, want %d", len(resp.Credentials), len(keys))
		}
		if n, err := alloc.Store.Reserved(ctx, "https://issuer.example.com/statuslists/1"); err != nil || n != len(keys) {
			t.Errorf("Reserved = %d, %v; want %d", n, err, len(keys))
		}
		if len(req.SDJWTClaims.Status) != 0 {
			t.Error("PerBatch's changes leaked into the request's shared claims")
		}
	})
	refused := map[string]struct {
		hook func(context.Context, []*issuer.CredentialInstance) error
		want string
	}{
		"error": {func(context.Context, []*issuer.CredentialInstance) error { return errors.New("lists full") }, "lists full"},
		"shared reference": {func(_ context.Context, b []*issuer.CredentialInstance) error {
			return eachStatus(b, func(int) int { return 7 })
		}, "same status reference"},
		"removed claims": {func(_ context.Context, b []*issuer.CredentialInstance) error {
			b[1].SDJWTClaims = nil
			return nil
		}, "removed"},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t)
			req, _ := batchRequest(t, f)
			req.PerBatch = tc.hook
			if _, err := f.iss.RequestCredential(ctx, batchAuth, req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

// eachStatus gives each Credential of batch the status index idx(i).
func eachStatus(batch []*issuer.CredentialInstance, idx func(i int) int) error {
	for i, c := range batch {
		c.SDJWTClaims.Status = statusRef(idx(i))
	}
	return nil
}

// A deferred issuance runs DeferredIssuance.PerBatch, as an immediate
// one runs CredentialRequest.PerBatch.
func TestIssueDeferredCredential_PerBatch(t *testing.T) {
	f := newDeferralFixture(t)
	ctx := context.Background()
	txID, _ := f.deferOne(t)
	calls := 0
	err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{
		SDJWTClaims: testSDJWTClaims(),
		PerBatch: func(_ context.Context, batch []*issuer.CredentialInstance) error {
			calls++
			return eachStatus(batch, func(i int) int { return 40 + i })
		},
	})
	if err != nil || calls != 1 {
		t.Fatalf("IssueDeferredCredential = %v, PerBatch called %d times", err, calls)
	}
}
