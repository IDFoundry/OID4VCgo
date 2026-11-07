//go:build mobiletest

package mobile

import (
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// Cancelling a presentation while its holder key's prompt shows
// dismisses the prompt through the CallbackCanceller, and Respond
// returns cancelled at once, sending nothing.
func TestSessions_CancelDismissesHolderPrompt(t *testing.T) {
	env, err := startTestEnv(walletflowtest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(env.Close)
	s := newPromptingKeyStore()
	s.prompting = false
	h := harness{env: env, keys: s.goKeyStore, creds: newGoCredentialStore()}
	if h.w, err = NewWallet(env.ConfigJSON(), s, h.creds, env.Provider()); err != nil {
		t.Fatal(err)
	}
	h.w.SetCallbackCanceller(s)
	var sdjwt string
	for _, c := range h.receive(t) {
		if c.Format == "dc+sd-jwt" {
			sdjwt = c.ID
		}
	}

	req := decode[struct{ ID, Link string }](t, mustText(t)(env.Request("")))
	p, err := h.w.StartPresentation(NewOperation(0), req.Link)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.prompting = true
	s.mu.Unlock()
	op := NewOperation(0)
	go func() {
		<-s.shown
		op.Cancel()
	}()
	start := time.Now()
	if _, err := p.Respond(op, `{"pid":["`+sdjwt+`"]}`); code(err) != CodeCancelled {
		t.Errorf("Respond cancelled at the prompt = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("Respond returned after %v", time.Since(start))
	}
	if len(s.cancels()) == 0 {
		t.Error("CancelKeyUse wasn't called")
	}
	if r := decode[struct{ Status string }](t, mustText(t)(env.RequestResult(req.ID))); r.Status == "done" {
		t.Errorf("the verifier got a presentation: %+v", r)
	}

	// Nothing was sent, so the holder can try again.
	close(s.answer)
	if _, err := p.Respond(NewOperation(0), `{"pid":["`+sdjwt+`"]}`); err != nil {
		t.Fatalf("Respond again = %v", err)
	}
	if r := decode[struct{ Status string }](t, mustText(t)(env.RequestResult(req.ID))); r.Status != "done" {
		t.Errorf("verifier after answering = %+v", r)
	}
}
