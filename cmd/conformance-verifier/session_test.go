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

func TestSessionStore_PendingDecryptionKeysExcludesDoneSessions(t *testing.T) {
	s := newSessionStore()
	pending := &session{id: "pending", createdAt: time.Now(), built: true}
	done := &session{id: "done", createdAt: time.Now(), built: true, done: true}
	s.put(pending)
	s.put(done)

	got := s.pendingDecryptionKeys()
	if len(got) != 1 || got[0].id != "pending" {
		t.Fatalf("pendingDecryptionKeys = %+v, want only the pending session", got)
	}
}

func TestSessionStore_PendingDecryptionKeysExcludesUnbuiltSessions(t *testing.T) {
	s := newSessionStore()
	unbuilt := &session{id: "unbuilt", createdAt: time.Now()}
	s.put(unbuilt)

	got := s.pendingDecryptionKeys()
	if len(got) != 0 {
		t.Fatalf("pendingDecryptionKeys = %+v, want none (session never fetched request_uri)", got)
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
