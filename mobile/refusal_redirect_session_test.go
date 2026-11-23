//go:build mobiletest

package mobile

import (
	"encoding/json"
	"testing"
)

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

// A refused request's redirect_uri the wallet doesn't follow — a system
// app's, or with verifier_redirect_schemes another scheme than those it
// names — isn't the Operation's to take, and StartPresentation still
// fails with request_refused.
func TestStartPresentation_RefusedRequestRedirectNotFollowed(t *testing.T) {
	h := newHarness(t, false)
	var cfg map[string]any
	if err := json.Unmarshal([]byte(h.env.ConfigJSON()), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["verifier_redirect_schemes"] = []string{"com.example.verifier"}
	narrowedJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	narrowed, err := NewWallet(string(narrowedJSON), newGoKeyStore(), newGoCredentialStore(), h.env.Provider())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		w              *Wallet
		redirect, want string
	}{
		{"a system app's", h.w, "market://details?id=com.attacker.app", ""},
		{"an app's", h.w, "com.other.app:/done", "com.other.app:/done"},
		{"an app's not named", narrowed, "com.other.app:/done", ""},
		{"an app's named", narrowed, "com.example.verifier:/done", "com.example.verifier:/done"},
	} {
		link, err := h.env.RefusedRequest(tc.redirect)
		if err != nil {
			t.Fatal(err)
		}
		op := NewOperation(0)
		if _, err := tc.w.StartPresentation(op, link); code(err) != CodeRequestRefused {
			t.Errorf("%s: StartPresentation = %v, want %s", tc.name, err, CodeRequestRefused)
		}
		if got := op.TakeRefusalRedirect(); got != tc.want {
			t.Errorf("%s: Operation's redirect = %q, want %q", tc.name, got, tc.want)
		}
	}
}
