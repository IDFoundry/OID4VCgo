package walletprovider

import (
	"fmt"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientAddress(t *testing.T) {
	for remote, want := range map[string]string{
		"192.0.2.7:443":                     "192.0.2.7",
		"[::ffff:192.0.2.7]:443":            "192.0.2.7",
		"[2001:db8:1:2:3:4:5:6]:443":        "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff:ffff:ffff:1]:1": "2001:db8:1:2::/64",
		"not an address":                    "not an address",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if got := clientAddress(r); got != want {
			t.Errorf("clientAddress(%q) = %q, want %q", remote, got, want)
		}
	}
}

func TestClientLimiter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newClientLimiter(challengeRate, challengeBurst)
	for i := range int(challengeBurst) {
		if !l.allow("a", now) {
			t.Fatalf("request %d refused within the burst", i)
		}
	}
	if l.allow("a", now) {
		t.Fatal("request past the burst allowed")
	}
	if !l.allow("a", now.Add(time.Second)) {
		t.Fatal("request a second later refused")
	}
}

// TestClientLimiter_FullTable checks a new client is let in when every
// tracked one has drained its bucket, by forgetting the one heard from
// least recently.
func TestClientLimiter_FullTable(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newClientLimiter(challengeRate, challengeBurst)
	for i := range maxLimitedClients {
		client := fmt.Sprint("client-", i)
		for range int(challengeBurst) {
			l.allow(client, now)
		}
	}
	if !l.allow("new", now) {
		t.Fatal("a new client was refused with the table full")
	}
	if len(l.buckets) != maxLimitedClients || l.recent.Len() != maxLimitedClients {
		t.Fatalf("tracking %d buckets (%d in the list), want %d", len(l.buckets), l.recent.Len(), maxLimitedClients)
	}
	if _, ok := l.buckets["client-0"]; ok {
		t.Error("the least recently heard client is still tracked")
	}
	if l.allow("client-1", now) {
		t.Error("a drained client still tracked was allowed")
	}
}
