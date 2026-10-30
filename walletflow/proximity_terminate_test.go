package walletflow_test

import (
	"context"
	"crypto"
	"errors"
	"io"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// promptKeys is a MemoryKeyStore whose keys, once armed, block in Sign
// until released: a holder key behind a biometric prompt.
type promptKeys struct {
	*walletflow.MemoryKeyStore
	armed   atomic.Bool
	release chan struct{}
	signing chan struct{}
}

type promptKey struct {
	walletflow.Key
	s *promptKeys
}

func (s *promptKeys) NewKey(ctx context.Context, p walletflow.KeyPurpose) (walletflow.Key, error) {
	k, err := s.MemoryKeyStore.NewKey(ctx, p)
	return promptKey{k, s}, err
}

func (s *promptKeys) Key(ctx context.Context, id string) (walletflow.Key, error) {
	k, err := s.MemoryKeyStore.Key(ctx, id)
	if err != nil {
		return nil, err
	}
	return promptKey{k, s}, nil
}

func (k promptKey) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	if k.s.armed.Load() {
		k.s.signing <- struct{}{}
		<-k.s.release
	}
	return k.Key.Sign(r, d, o)
}

// Terminate, called while Respond waits on the holder key's prompt,
// wins: Respond fails with ErrTerminated and gives nothing to send.
func TestProximityRespond_TerminatedDuringPrompt(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	keys := &promptKeys{MemoryKeyStore: f.keys, release: make(chan struct{}), signing: make(chan struct{}, 1)}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots, Development: true,
	}, walletflow.Dependencies{Keys: keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	mdocID := heldMdoc(t, receive(t, f, w, walletflowtest.MdocConfigurationID))
	ctx := context.Background()
	p, err := w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	_, msg := proximityRequest(t, p, nil)
	if ev := p.HandleMessage(ctx, msg); !ev.Request {
		t.Fatalf("event %+v", ev)
	}
	keys.armed.Store(true)
	type result struct {
		presented walletflow.ProximityPresented
		err       error
	}
	done := make(chan result, 1)
	go func() {
		pr, err := p.Respond(ctx, 0, mdocID, familyName())
		done <- result{pr, err}
	}()
	<-keys.signing // the prompt is up
	terminated := make(chan []byte, 1)
	go func() { terminated <- p.Terminate() }()
	// Terminate sets its flag before it waits for Respond; give it the
	// moment it takes to get there, then let the holder approve.
	for !walletflow.Terminating(p) {
		select {
		case m := <-terminated:
			t.Fatalf("Terminate returned %x before Respond", m)
		default:
			runtime.Gosched()
		}
	}
	close(keys.release)
	res := <-done
	if !errors.Is(res.err, walletflow.ErrTerminated) || res.presented.Send != nil {
		t.Fatalf("Respond after Terminate: %v, Send %x; want ErrTerminated and nothing to send", res.err, res.presented.Send)
	}
	if m := <-terminated; len(m) == 0 {
		t.Fatal("Terminate gave no termination message")
	}
	if _, err := p.Respond(ctx, 0, mdocID, familyName()); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Fatalf("Respond after the session ended: %v, want ErrWrongStep", err)
	}
}
