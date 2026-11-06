package statuscache

import (
	"context"
	"errors"
	"testing"
	"time"
)

// server is a status list server whose token has an ETag, and that
// answers a fetch revalidating it with a 304.
type server struct {
	token   string
	maxAge  *time.Duration
	fetches []Validators
}

func (s *server) fetch(_ context.Context, held Validators) (Fetched, error) {
	s.fetches = append(s.fetches, held)
	etag := `"` + s.token + `"`
	if held.ETag == etag {
		return Fetched{NotModified: true, MaxAge: s.maxAge}, nil
	}
	return Fetched{Token: []byte(s.token), Validators: Validators{ETag: etag}, MaxAge: s.maxAge}, nil
}

// An entry past MaxAge is revalidated, not fetched again: a 304 keeps
// it, checked again by recheck, for another MaxAge; a changed token is
// fetched in full.
func TestCheck_Revalidates(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{MaxAge: time.Minute, Now: func() time.Time { return now }})
	s := &server{token: "v1"}
	ctx := context.Background()
	v := Verified{Iat: now.Unix(), Exp: ptr(now.Unix() + 3600)}
	var n counter
	check := func() error { return c.Check(ctx, "u", "m", "", s.fetch, n.verify(v, nil), n.rechecks(nil)) }
	if err := check(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if err := check(); err != nil {
		t.Fatal(err)
	}
	if len(s.fetches) != 2 || s.fetches[1].ETag != `"v1"` {
		t.Fatalf("fetches %v, want the second to revalidate v1", s.fetches)
	}
	if n.verifies != 1 || n.recheck != 1 {
		t.Errorf("%d verifies and %d rechecks, want 1 and 1: a 304 rechecks the memo", n.verifies, n.recheck)
	}
	// Kept for another MaxAge from the 304.
	now = now.Add(30 * time.Second)
	if err := check(); err != nil || len(s.fetches) != 2 {
		t.Errorf("Check = %v after %d fetches, want the revalidated entry used", err, len(s.fetches))
	}
	s.token = "v2"
	now = now.Add(time.Minute)
	if err := check(); err != nil {
		t.Fatal(err)
	}
	if n.verifies != 2 {
		t.Errorf("%d verifies, want a changed token verified in full", n.verifies)
	}
}

// A 304 for a token a check now refuses — past its exp, say — fails the
// check, and the next check fetches the token in full.
func TestCheck_NotModifiedRefused(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{MaxAge: time.Minute, Now: func() time.Time { return now }})
	s := &server{token: "v1"}
	ctx := context.Background()
	v := Verified{Iat: now.Unix(), Exp: ptr(now.Unix() + 3600)}
	var n counter
	if err := c.Check(ctx, "u", "m", "", s.fetch, n.verify(v, nil), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	expired := errors.New("expired")
	if err := c.Check(ctx, "u", "m", "", s.fetch, n.verify(Verified{}, expired), n.rechecks(expired)); !errors.Is(err, expired) {
		t.Fatalf("Check = %v, want the recheck's error", err)
	}
	if got := s.fetches[1]; got.ETag == "" {
		t.Fatalf("the second fetch didn't revalidate")
	}
	_ = c.Check(ctx, "u", "m", "", s.fetch, n.verify(Verified{}, expired), n.rechecks(expired))
	if got := s.fetches[len(s.fetches)-1]; got != (Validators{}) {
		t.Errorf("fetch after a refused 304 revalidated %v, want an unconditional fetch", got)
	}
}

// A response's max-age shortens how long its token is kept, and never
// lengthens it past MaxAge.
func TestCheck_MaxAgeHonoured(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{MaxAge: time.Minute, Now: func() time.Time { return now }})
	short := 10 * time.Second
	s := &server{token: "v1", maxAge: &short}
	ctx := context.Background()
	v := Verified{Iat: now.Unix()}
	var n counter
	check := func() error { return c.Check(ctx, "u", "m", "", s.fetch, n.verify(v, nil), n.rechecks(nil)) }
	_ = check()
	now = now.Add(11 * time.Second)
	_ = check()
	if len(s.fetches) != 2 {
		t.Errorf("%d fetches, want the token revalidated after its max-age", len(s.fetches))
	}
	long := time.Hour
	s.maxAge = &long
	now = now.Add(11 * time.Second)
	_ = check()
	now = now.Add(2 * time.Minute)
	_ = check()
	if len(s.fetches) != 4 {
		t.Errorf("%d fetches, want MaxAge to bound a longer max-age", len(s.fetches))
	}
}

// A 304 to an unconditional fetch fails the check.
func TestCheck_UnaskedNotModified(t *testing.T) {
	c := New(Options{})
	fetch := func(context.Context, Validators) (Fetched, error) { return Fetched{NotModified: true}, nil }
	var n counter
	if err := c.Check(context.Background(), "u", "m", "", fetch, n.verify(Verified{}, nil), n.rechecks(nil)); err == nil {
		t.Error("an unasked-for 304 passed")
	}
}
