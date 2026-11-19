//go:build mobiletest

package mobile

import "testing"

// A request the wallet refuses fails StartPresentation with
// request_refused, and the redirect_uri the Verifier answered with is
// the call's Operation's, once, and the Wallet's.
func TestStartPresentation_RefusedRequestRedirect(t *testing.T) {
	h := newHarness(t, false)
	link, err := h.env.RefusedRequest("https://verifier.example/done")
	if err != nil {
		t.Fatal(err)
	}
	op := NewOperation(0)
	if _, err := h.w.StartPresentation(op, link); code(err) != CodeRequestRefused {
		t.Fatalf("StartPresentation = %v, want %s", err, CodeRequestRefused)
	}
	if got := op.TakeRefusalRedirect(); got != "https://verifier.example/done" {
		t.Errorf("Operation's redirect = %q", got)
	}
	if got := op.TakeRefusalRedirect(); got != "" {
		t.Errorf("Operation's redirect, again = %q, want none", got)
	}
	if got := h.w.TakeRefusalRedirect(); got != "https://verifier.example/done" {
		t.Errorf("Wallet's redirect = %q", got)
	}
}
