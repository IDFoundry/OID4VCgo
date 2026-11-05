package statuslist

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// A cached token past MaxAge is revalidated with If-None-Match: a 304
// keeps it for another MaxAge, in both forms.
func TestCache_Revalidates(t *testing.T) {
	for _, cwt := range []bool{false, true} {
		s := newCacheServer(t)
		s.set(func(s *cacheServer) { s.etag = true })
		c := s.checker(NewCache(CacheOptions{MaxAge: time.Minute, Now: s.clock.Now}))
		s.check(t, c, "/l", 0, cwt)
		s.clock.Add(time.Minute)
		if got := s.check(t, c, "/l", 1, cwt); got != StatusInvalid {
			t.Errorf("cwt=%v: index 1 is %v after a 304", cwt, got)
		}
		if got := s.notModifieds.Load(); got != 1 {
			t.Errorf("cwt=%v: %d 304s, want the expired token revalidated", cwt, got)
		}
		s.clock.Add(time.Minute - time.Second)
		s.check(t, c, "/l", 0, cwt)
		s.wantFetches(t, 2, "within MaxAge of the 304")
	}
}

// A 304 for a token past its exp fails the check: the server still
// serving it doesn't make it current.
func TestCache_NotModifiedExpired(t *testing.T) {
	s := newCacheServer(t)
	s.set(func(s *cacheServer) { s.etag, s.expIn = true, 2*time.Minute })
	c := s.checker(NewCache(CacheOptions{MaxAge: time.Minute, Now: s.clock.Now}))
	s.check(t, c, "/l", 0, false)
	s.clock.Add(3 * time.Minute)
	if _, _, err := c.Check(context.Background(), StatusListRef{Idx: 0, URI: s.uri("/l")}, false); err == nil {
		t.Error("a 304 for an expired token passed")
	}
	if got := s.notModifieds.Load(); got != 1 {
		t.Errorf("%d 304s, want the expired token revalidated once", got)
	}
}

// A response's Cache-Control max-age, less its Age, shortens how long
// its token is kept.
func TestCache_HonoursMaxAge(t *testing.T) {
	s := newCacheServer(t)
	s.set(func(s *cacheServer) { s.cacheControl = "public, max-age=20" })
	c := s.checker(NewCache(CacheOptions{Now: s.clock.Now}))
	s.check(t, c, "/l", 0, false)
	s.clock.Add(19 * time.Second)
	s.check(t, c, "/l", 0, false)
	s.wantFetches(t, 1, "within max-age")
	s.clock.Add(time.Second)
	s.check(t, c, "/l", 0, false)
	s.wantFetches(t, 2, "at max-age")
}

func TestFreshFor(t *testing.T) {
	for name, tc := range map[string]struct {
		header http.Header
		want   time.Duration // -1: none
	}{
		"none":         {http.Header{}, -1},
		"max-age":      {http.Header{"Cache-Control": {"public, max-age=60"}}, time.Minute},
		"Age":          {http.Header{"Cache-Control": {"max-age=60"}, "Age": {"15"}}, 45 * time.Second},
		"Age past":     {http.Header{"Cache-Control": {"max-age=60"}, "Age": {"90"}}, -30 * time.Second},
		"invalid":      {http.Header{"Cache-Control": {"max-age=soon"}}, 0},
		"quoted":       {http.Header{"Cache-Control": {`max-age="30"`}}, 30 * time.Second},
		"two headers":  {http.Header{"Cache-Control": {"public", "Max-Age=5"}}, 5 * time.Second},
		"no-cache too": {http.Header{"Cache-Control": {"no-cache"}}, -1},
	} {
		got := freshFor(tc.header)
		switch {
		case tc.want == -1 && got != nil:
			t.Errorf("%s: %v, want none", name, *got)
		case tc.want != -1 && (got == nil || *got != tc.want):
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
