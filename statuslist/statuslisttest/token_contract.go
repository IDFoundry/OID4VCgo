package statuslisttest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// TestTokenStoreContract checks that the stores newStore returns
// behave as statuslist.TokenStore requires. newStore returns a store,
// and bump, a function that changes a status of the list at uri as the
// store's versions follow (nil for a store that keeps no versions).
// Each case uses lists of its own, so newStore may return stores
// sharing one database.
func TestTokenStoreContract(t *testing.T, newStore func(t *testing.T) (store statuslist.TokenStore, bump func(t *testing.T, uri string))) {
	t.Helper()
	cases := []struct {
		name string
		run  func(*testing.T, statuslist.TokenStore, func(*testing.T, string), string)
	}{
		{"Empty", tokenEmpty},
		{"PutAndRead", tokenPutAndRead},
		{"OnlyNewerReplaces", tokenOnlyNewerReplaces},
		{"Lease", tokenLease},
		{"PutEndsLease", tokenPutEndsLease},
		{"OneConcurrentClaim", tokenOneConcurrentClaim},
		{"FormsAndListsApart", tokenFormsAndListsApart},
		{"Versions", tokenVersions},
		{"Signers", tokenSigners},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, bump := newStore(t)
			tc.run(t, s, bump, "https://issuer.example/statuslists/token-"+tc.name)
		})
	}
}

// tokenTime is a time with the millisecond precision a TokenStore
// keeps.
var tokenTime = time.UnixMilli(1_900_000_000_123)

func storedToken(b string, version int64, signedAt time.Time) statuslist.StoredToken {
	signer := sha256.Sum256([]byte("signer of " + b))
	return statuslist.StoredToken{Bytes: []byte(b), Version: version, SignedAt: signedAt, Exp: signedAt.Add(time.Hour), Signer: signer[:]}
}

func mustPut(t *testing.T, s statuslist.TokenStore, uri string, form statuslist.Form, holder string, token statuslist.StoredToken) {
	t.Helper()
	if err := s.Put(context.Background(), uri, form, holder, token); err != nil {
		t.Fatalf("Put: %v", err)
	}
}

func mustClaim(t *testing.T, s statuslist.TokenStore, uri string, form statuslist.Form, holder string, now time.Time, want bool) {
	t.Helper()
	got, err := s.Claim(context.Background(), uri, form, holder, now, now.Add(time.Minute))
	if err != nil || got != want {
		t.Fatalf("Claim(%s at %s) = %v, %v; want %v", holder, now, got, err, want)
	}
}

// expectToken checks the token stored for form, in both Head and Token.
func expectToken(t *testing.T, s statuslist.TokenStore, uri string, form statuslist.Form, want statuslist.StoredToken) {
	t.Helper()
	ctx := context.Background()
	head, err := s.Head(ctx, uri, form)
	switch {
	case err != nil:
		t.Fatalf("Head: %v", err)
	case !head.Stored || head.Token.Version != want.Version || !head.Token.SignedAt.Equal(want.SignedAt) || !head.Token.Exp.Equal(want.Exp) || !bytes.Equal(head.Token.Signer, want.Signer):
		t.Fatalf("Head = %+v, want the token %d signed at %s by %x", head, want.Version, want.SignedAt, want.Signer)
	}
	got, ok, err := s.Token(ctx, uri, form)
	if err != nil || !ok || !bytes.Equal(got.Bytes, want.Bytes) || got.Version != want.Version || !got.SignedAt.Equal(want.SignedAt) || !got.Exp.Equal(want.Exp) || !bytes.Equal(got.Signer, want.Signer) {
		t.Fatalf("Token = %q %d %s %s %x, %v, %v; want %q %d %s %s %x", got.Bytes, got.Version, got.SignedAt, got.Exp, got.Signer, ok, err, want.Bytes, want.Version, want.SignedAt, want.Exp, want.Signer)
	}
}

// A list never seen is at version zero, with no token, and a lease
// taken stores none.
func tokenEmpty(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	ctx := context.Background()
	if head, err := s.Head(ctx, uri, statuslist.FormJWT); err != nil || head.Stored || head.Version != 0 {
		t.Fatalf("Head of an unseen list = %+v, %v", head, err)
	}
	mustClaim(t, s, uri, statuslist.FormJWT, "a", tokenTime, true)
	if head, err := s.Head(ctx, uri, statuslist.FormJWT); err != nil || head.Stored {
		t.Fatalf("Head after a Claim alone = %+v, %v", head, err)
	}
	if _, ok, err := s.Token(ctx, uri, statuslist.FormJWT); err != nil || ok {
		t.Fatalf("Token after a Claim alone = %v, %v", ok, err)
	}
}

// A token put is read back, to the millisecond, with or without a
// lease taken first.
func tokenPutAndRead(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	token := storedToken("jwt-1", 0, tokenTime)
	mustPut(t, s, uri, statuslist.FormJWT, "a", token)
	expectToken(t, s, uri, statuslist.FormJWT, token)
	mustClaim(t, s, uri, statuslist.FormCWT, "a", tokenTime, true)
	cwt := storedToken("cwt-1", 0, tokenTime)
	mustPut(t, s, uri, statuslist.FormCWT, "a", cwt)
	expectToken(t, s, uri, statuslist.FormCWT, cwt)
}

// A token replaces the stored one only when it's newer: signed from a
// later version, or from the same one later.
func tokenOnlyNewerReplaces(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	first := storedToken("v1", 1, tokenTime)
	mustPut(t, s, uri, statuslist.FormJWT, "a", first)
	mustPut(t, s, uri, statuslist.FormJWT, "b", storedToken("older version", 0, tokenTime.Add(time.Minute)))
	mustPut(t, s, uri, statuslist.FormJWT, "b", storedToken("earlier", 1, tokenTime.Add(-time.Millisecond)))
	mustPut(t, s, uri, statuslist.FormJWT, "b", storedToken("same", 1, tokenTime))
	expectToken(t, s, uri, statuslist.FormJWT, first)
	later := storedToken("later", 1, tokenTime.Add(time.Millisecond))
	mustPut(t, s, uri, statuslist.FormJWT, "b", later)
	expectToken(t, s, uri, statuslist.FormJWT, later)
	newer := storedToken("newer version", 2, tokenTime.Add(-time.Hour))
	mustPut(t, s, uri, statuslist.FormJWT, "a", newer)
	expectToken(t, s, uri, statuslist.FormJWT, newer)
}

// A lease is its holder's until it ends: another holder's Claim fails
// until then, and the holder's own succeeds.
func tokenLease(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	mustClaim(t, s, uri, statuslist.FormJWT, "a", tokenTime, true)
	mustClaim(t, s, uri, statuslist.FormJWT, "b", tokenTime.Add(59*time.Second), false)
	mustClaim(t, s, uri, statuslist.FormJWT, "a", tokenTime.Add(30*time.Second), true) // now until +90s
	mustClaim(t, s, uri, statuslist.FormJWT, "b", tokenTime.Add(89*time.Second), false)
	mustClaim(t, s, uri, statuslist.FormJWT, "b", tokenTime.Add(90*time.Second), true)
	mustClaim(t, s, uri, statuslist.FormJWT, "a", tokenTime.Add(91*time.Second), false)
}

// Put ends its holder's lease, newer or not, and leaves another's.
func tokenPutEndsLease(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	mustClaim(t, s, uri, statuslist.FormJWT, "a", tokenTime, true)
	mustPut(t, s, uri, statuslist.FormJWT, "b", storedToken("b's", 0, tokenTime))
	mustClaim(t, s, uri, statuslist.FormJWT, "b", tokenTime, false)
	mustPut(t, s, uri, statuslist.FormJWT, "a", storedToken("a's, older", 0, tokenTime.Add(-time.Second)))
	mustClaim(t, s, uri, statuslist.FormJWT, "b", tokenTime, true)
}

// Of concurrent Claims with no live lease, one succeeds.
func tokenOneConcurrentClaim(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	const claimers = 8
	var wg sync.WaitGroup
	results := make([]bool, claimers)
	errs := make([]error, claimers)
	for i := range claimers {
		wg.Go(func() {
			results[i], errs[i] = s.Claim(context.Background(), uri, statuslist.FormJWT, "holder-"+strconv.Itoa(i), tokenTime, tokenTime.Add(time.Minute))
		})
	}
	wg.Wait()
	won := 0
	for i := range claimers {
		if errs[i] != nil {
			t.Fatalf("Claim %d: %v", i, errs[i])
		}
		if results[i] {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d concurrent Claims succeeded, want 1", won)
	}
}

// Each list's form has its own token and lease.
func tokenFormsAndListsApart(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	other := uri + "-other"
	mustClaim(t, s, uri, statuslist.FormJWT, "a", tokenTime, true)
	mustClaim(t, s, uri, statuslist.FormCWT, "b", tokenTime, true)
	mustClaim(t, s, other, statuslist.FormJWT, "b", tokenTime, true)
	jwt := storedToken("jwt", 0, tokenTime)
	mustPut(t, s, uri, statuslist.FormJWT, "a", jwt)
	for _, l := range []struct {
		uri  string
		form statuslist.Form
	}{{uri, statuslist.FormCWT}, {other, statuslist.FormJWT}, {other, statuslist.FormCWT}} {
		if head, err := s.Head(context.Background(), l.uri, l.form); err != nil || head.Stored {
			t.Fatalf("Head(%s, %v) = %+v, %v; want no token", l.uri, l.form, head, err)
		}
	}
	expectToken(t, s, uri, statuslist.FormJWT, jwt)
}

// A status change raises the list's version, for every form, and no
// other list's.
func tokenVersions(t *testing.T, s statuslist.TokenStore, bump func(*testing.T, string), uri string) {
	if bump == nil {
		t.Skip("the store keeps no versions")
	}
	ctx := context.Background()
	version := func(uri string, form statuslist.Form) int64 {
		t.Helper()
		head, err := s.Head(ctx, uri, form)
		if err != nil {
			t.Fatalf("Head: %v", err)
		}
		return head.Version
	}
	other := uri + "-other"
	bump(t, other) // so other is a list the store has seen
	before, otherBefore := version(uri, statuslist.FormJWT), version(other, statuslist.FormJWT)
	bump(t, uri)
	afterJWT, afterCWT := version(uri, statuslist.FormJWT), version(uri, statuslist.FormCWT)
	if afterJWT <= before || afterCWT != afterJWT {
		t.Fatalf("versions after a status change: %d (JWT), %d (CWT); before %d", afterJWT, afterCWT, before)
	}
	if v := version(other, statuslist.FormJWT); v != otherBefore {
		t.Fatalf("another list's version went from %d to %d", otherBefore, v)
	}
	bump(t, uri)
	if v := version(uri, statuslist.FormJWT); v <= afterJWT {
		t.Fatalf("version after a second change = %d, want above %d", v, afterJWT)
	}
}

// A token's signer is kept with it, and replaced with it: a newer token
// another signer signed replaces the stored one, signer and all. A
// token with no signer reads back with none.
func tokenSigners(t *testing.T, s statuslist.TokenStore, _ func(*testing.T, string), uri string) {
	first := storedToken("first signer's", 0, tokenTime)
	mustPut(t, s, uri, statuslist.FormJWT, "a", first)
	expectToken(t, s, uri, statuslist.FormJWT, first)
	rotated := storedToken("second signer's", 0, tokenTime.Add(time.Millisecond))
	if bytes.Equal(rotated.Signer, first.Signer) {
		t.Fatal("the two tokens should have different signers")
	}
	mustPut(t, s, uri, statuslist.FormJWT, "b", rotated)
	expectToken(t, s, uri, statuslist.FormJWT, rotated)

	unsigned := storedToken("no signer", 0, tokenTime)
	unsigned.Signer = nil
	mustPut(t, s, uri, statuslist.FormCWT, "a", unsigned)
	got, ok, err := s.Token(context.Background(), uri, statuslist.FormCWT)
	if err != nil || !ok || len(got.Signer) != 0 {
		t.Fatalf("Token with no signer = %x, %v, %v; want none", got.Signer, ok, err)
	}
}
