package statuscache

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"
)

func ptr(v int64) *int64 { return &v }

func TestExpiry(t *testing.T) {
	at := time.Unix(1_000_000, 0)
	c := New(Options{MaxAge: time.Hour})
	for name, tc := range map[string]struct {
		v    Verified
		want time.Time
	}{
		"MaxAge alone":    {Verified{Iat: at.Unix()}, at.Add(time.Hour)},
		"exp first":       {Verified{Iat: at.Unix(), Exp: ptr(at.Unix() + 60)}, at.Add(time.Minute)},
		"ttl first":       {Verified{Iat: at.Unix() - 30, TTL: ptr(60), Exp: ptr(at.Unix() + 600)}, at.Add(30 * time.Second)},
		"ttl overflowing": {Verified{Iat: at.Unix(), TTL: ptr(math.MaxInt64)}, at.Add(time.Hour)},
	} {
		if got := c.expiry(tc.v, at); !got.Equal(tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// A token already expired when its fetch finished isn't stored, and a
// failed verification returns its error.
func TestCheck_NotStored(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{Now: func() time.Time { return now }})
	fetch := func(context.Context) ([]byte, error) { return []byte("token"), nil }
	expired := func([]byte, any) (Verified, error) { return Verified{Iat: now.Unix() - 120, TTL: ptr(60)}, nil }
	if err := c.Check(context.Background(), "u", "m", "", fetch, expired); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.Len(); n != 0 {
		t.Errorf("an expired token was stored")
	}
	refused := errors.New("refused")
	if err := c.Check(context.Background(), "u", "m", "", fetch, func([]byte, any) (Verified, error) { return Verified{}, refused }); !errors.Is(err, refused) {
		t.Errorf("Check = %v, want the verification's error", err)
	}
	if n, _ := c.Len(); n != 0 {
		t.Errorf("a refused token was stored")
	}
}
