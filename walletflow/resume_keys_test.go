package walletflow_test

import (
	"context"
	"crypto"
	"errors"
	"io"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// strictKeys is a MemoryKeyStore whose keys stop signing once deleted, as
// a platform key store's do (the key lives in the Secure Enclave).
type strictKeys struct{ *walletflow.MemoryKeyStore }

type strictKey struct {
	walletflow.Key
	s *walletflow.MemoryKeyStore
}

func (k strictKey) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if _, err := k.s.Key(context.Background(), k.ID()); err != nil {
		return nil, errors.New("the key was deleted")
	}
	return k.Key.Sign(r, d, o)
}

func (s strictKeys) NewKey(ctx context.Context, p walletflow.KeyPurpose) (walletflow.Key, error) {
	k, err := s.MemoryKeyStore.NewKey(ctx, p)
	if err != nil {
		return nil, err
	}
	return strictKey{k, s.MemoryKeyStore}, nil
}

func (s strictKeys) Key(ctx context.Context, id string) (walletflow.Key, error) {
	k, err := s.MemoryKeyStore.Key(ctx, id)
	if err != nil {
		return nil, err
	}
	return strictKey{k, s.MemoryKeyStore}, nil
}

// newStrictWallet is a wallet whose keys stop signing once deleted.
func newStrictWallet(t *testing.T, env testEnv) (*walletflow.Wallet, *walletflow.MemoryKeyStore) {
	t.Helper()
	mem := walletflow.NewMemoryKeyStore()
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, CredentialIssuers: []string{env.IssuerURL}, IssuerRoots: env.IssuerRoots, Development: true,
	}, walletflow.Dependencies{Keys: strictKeys{mem}, Credentials: walletflow.NewMemoryCredentialStore(), Provider: env.Provider, HTTP: env.HTTP, Authorizations: walletflow.NewMemoryAuthorizationStore()})
	if err != nil {
		t.Fatal(err)
	}
	return w, mem
}

// approvedRedirect begins an authorization on w and returns the issuance
// and the authorization server's redirect back.
func approvedRedirect(t *testing.T, env testEnv, w *walletflow.Wallet) (*walletflow.Issuance, string) {
	t.Helper()
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := env.Approve(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}
	return s, redirect
}

// Closing the issuance that began an authorization, after it was
// resumed, leaves the resumed one its keys.
func TestResumeIssuance_ClosingTheOriginalKeepsTheKeys(t *testing.T) {
	env := newEnv(t, walletflowtest.Options{})
	ctx := context.Background()
	w, _ := newStrictWallet(t, env)
	original, redirect := approvedRedirect(t, env, w)
	resumed, err := w.ResumeIssuance(ctx, redirect)
	if err != nil {
		t.Fatalf("ResumeIssuance: %v", err)
	}
	_ = original.Close(ctx)
	if res, err := resumed.RequestCredentials(ctx); err != nil || len(res.Credentials) == 0 {
		t.Errorf("the resumed issuance after the original closed: %d credentials, %v", len(res.Credentials), err)
	}
	_ = resumed.Close(ctx)
}

// A redirect delivered twice at once resumes once: the other is refused
// before it rebuilds the issuance over the same keys, and the one that
// resumed keeps them.
func TestResumeIssuance_DeliveredTwice(t *testing.T) {
	env := newEnv(t, walletflowtest.Options{})
	ctx := context.Background()
	w, _ := newStrictWallet(t, env)
	_, redirect := approvedRedirect(t, env, w) // the app relaunched: dropped
	type outcome struct {
		s   *walletflow.Issuance
		err error
	}
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			s, err := w.ResumeIssuance(ctx, redirect)
			results <- outcome{s, err}
		}()
	}
	var winners []*walletflow.Issuance
	for range 2 {
		if o := <-results; o.err == nil {
			winners = append(winners, o.s)
		} else if !errors.Is(o.err, walletflow.ErrNoAuthorization) {
			t.Errorf("the second resume: %v, want ErrNoAuthorization", o.err)
		}
	}
	if len(winners) != 1 {
		t.Fatalf("%d resumes succeeded, want 1", len(winners))
	}
	if res, err := winners[0].RequestCredentials(ctx); err != nil || len(res.Credentials) == 0 {
		t.Errorf("the resumed issuance: %d credentials, %v", len(res.Credentials), err)
	}
	_ = winners[0].Close(ctx)
}
