package main

import (
	"testing"
	"time"
)

func TestSessionStore_PutThenGet(t *testing.T) {
	s := newSessionStore()
	sess := &session{id: "abc", createdAt: time.Now()}
	s.put(sess)

	got, ok := s.get("abc")
	if !ok {
		t.Fatalf("get(%q) = not found", "abc")
	}
	if got != sess {
		t.Fatalf("get returned a different session")
	}
}

func TestSessionStore_GetUnknownID(t *testing.T) {
	s := newSessionStore()
	if _, ok := s.get("never-put"); ok {
		t.Fatalf("get(unknown) = found, want not found")
	}
}

func TestSessionStore_PendingByKeyIDExcludesDoneSessions(t *testing.T) {
	s := newSessionStore()
	pending := &session{id: "pending", createdAt: time.Now(), built: true, keyID: "kid-pending"}
	done := &session{id: "done", createdAt: time.Now(), built: true, keyID: "kid-done", done: true}
	for _, sess := range []*session{pending, done} {
		s.put(sess)
		s.index(sess)
	}

	if got, ok := s.pendingByKeyID("kid-pending"); !ok || got != pending {
		t.Fatalf("pendingByKeyID(kid-pending) = %v, %v; want the pending session", got, ok)
	}
	if _, ok := s.pendingByKeyID("kid-done"); ok {
		t.Fatal("pendingByKeyID(kid-done) = found, want an answered session refused")
	}
	if _, ok := s.pendingByKeyID("kid-unknown"); ok {
		t.Fatal("pendingByKeyID(kid-unknown) = found")
	}
}

func TestSessionStore_PendingByKeyIDExcludesUnbuiltSessions(t *testing.T) {
	s := newSessionStore()
	unbuilt := &session{id: "unbuilt", createdAt: time.Now()}
	s.put(unbuilt)
	s.index(unbuilt)

	if _, ok := s.pendingByKeyID(""); ok {
		t.Fatal("pendingByKeyID(\"\") = found, want none (session never fetched request_uri)")
	}
}

func TestSessionStore_PutSweepsExpiredSessions(t *testing.T) {
	s := newSessionStore()
	expired := &session{id: "expired", createdAt: time.Now().Add(-2 * sessionTTL)}
	s.put(expired)
	s.put(&session{id: "fresh", createdAt: time.Now()})

	if _, ok := s.get("expired"); ok {
		t.Fatalf("get(expired) = found, want swept away by the second put")
	}
	if _, ok := s.get("fresh"); !ok {
		t.Fatalf("get(fresh) = not found, want found")
	}
}

func TestSessionStore_PutSweepsExpiredKeyIDs(t *testing.T) {
	s := newSessionStore()
	expired := &session{id: "expired", createdAt: time.Now().Add(-2 * sessionTTL), built: true, keyID: "kid-expired"}
	s.put(expired)
	s.index(expired)
	s.put(&session{id: "fresh", createdAt: time.Now()})

	if _, ok := s.pendingByKeyID("kid-expired"); ok {
		t.Fatal("pendingByKeyID(kid-expired) = found, want swept away by the second put")
	}
}
