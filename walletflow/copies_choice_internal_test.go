package walletflow

import (
	"testing"
	"time"
)

// A copy still valid is presented before an expired one, however the
// two have been used; among valid ones, the first unpresented, then the
// least shown.
func TestNextCopy_PrefersValidCopies(t *testing.T) {
	now := time.Now()
	c := StoredCredential{Copies: []CredentialCopy{
		{HolderKeyID: "expired", ValidUntil: now.Add(-time.Hour)},
		{HolderKeyID: "shown twice", Presented: true, ShownTo: []string{"x", "y"}, ValidUntil: now.Add(time.Hour)},
		{HolderKeyID: "shown once", Presented: true, ShownTo: []string{"x"}, ValidUntil: now.Add(time.Hour)},
	}}
	if _, cp := c.nextCopy("v", now); cp.HolderKeyID != "shown once" {
		t.Errorf("nextCopy = %q, want the valid copy shown to fewest", cp.HolderKeyID)
	}
	c.Copies = append(c.Copies, CredentialCopy{HolderKeyID: "fresh", ValidUntil: now.Add(time.Hour)})
	if _, cp := c.nextCopy("v", now); cp.HolderKeyID != "fresh" {
		t.Errorf("nextCopy = %q, want the unpresented valid copy", cp.HolderKeyID)
	}
	// Per Verifier: the copy it saw, unless that one has expired.
	c.Copies[0].ShownTo = []string{"v"}
	if _, cp, reused := c.copyFor(CopyPerVerifier, "v", now); reused || cp.HolderKeyID == "expired" {
		t.Errorf("copyFor = %q (reused %v), want a valid copy instead of the expired one it saw", cp.HolderKeyID, reused)
	}
}

// A copy CheckStatus found revoked is passed over like an expired one,
// even unpresented, and even for the Verifier that saw it; a credential
// with no other copy left isn't presentable.
func TestNextCopy_PassesOverRevokedCopies(t *testing.T) {
	now := time.Now()
	c := StoredCredential{Copies: []CredentialCopy{
		{HolderKeyID: "revoked", Revoked: true, ShownTo: []string{"v"}, ValidUntil: now.Add(time.Hour)},
		{HolderKeyID: "shown", Presented: true, ShownTo: []string{"x"}, ValidUntil: now.Add(time.Hour)},
	}}
	if _, cp := c.nextCopy("v", now); cp.HolderKeyID != "shown" {
		t.Errorf("nextCopy = %q, want the valid copy over the revoked one", cp.HolderKeyID)
	}
	if _, cp, reused := c.copyFor(CopyPerVerifier, "v", now); reused || cp.HolderKeyID != "shown" {
		t.Errorf("copyFor = %q (reused %v), want the valid copy instead of the revoked one it saw", cp.HolderKeyID, reused)
	}
	if !c.Presentable(now) {
		t.Error("Presentable = false with a valid copy left")
	}
	c.Copies[1].ValidUntil = now.Add(-time.Minute)
	if c.Presentable(now) {
		t.Error("Presentable = true with only a revoked and an expired copy")
	}
	single := StoredCredential{Credential: "c", Status: CredentialStatus{Value: StatusSuspended}}
	if single.Presentable(now) {
		t.Error("Presentable = true for a suspended credential")
	}
}

// Once every copy has been presented, a Verifier is given back a copy
// only it has seen, if any, rather than one another Verifier has: that
// links it to nothing new.
func TestNextCopy_PrefersACopyOnlyThisVerifierSaw(t *testing.T) {
	now := time.Now()
	a, b := VerifierHash("A"), VerifierHash("B")
	c := StoredCredential{Copies: []CredentialCopy{
		{HolderKeyID: "B's", Presented: true, ShownTo: []string{b}},
		{HolderKeyID: "A's", Presented: true, ShownTo: []string{a}},
	}}
	if _, cp := c.nextCopy(a, now); cp.HolderKeyID != "A's" {
		t.Errorf("nextCopy to A = %q, want the copy only A saw", cp.HolderKeyID)
	}
	if _, cp := c.nextCopy(b, now); cp.HolderKeyID != "B's" {
		t.Errorf("nextCopy to B = %q, want the copy only B saw", cp.HolderKeyID)
	}
	w := &Wallet{deps: Dependencies{Clock: func() time.Time { return now }}}
	if w.linkable(c, a) {
		t.Error("presenting to A again is reported linkable")
	}
	// A third Verifier gets the first of the least shown.
	if _, cp := c.nextCopy(VerifierHash("C"), now); cp.HolderKeyID != "B's" {
		t.Errorf("nextCopy to C = %q, want the first least shown", cp.HolderKeyID)
	}
}
