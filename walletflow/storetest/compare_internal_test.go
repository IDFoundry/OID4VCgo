package storetest

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// TestFixturesAreFull: every full fixture sets every field, and the
// check names a field left unset.
func TestFixturesAreFull(t *testing.T) {
	for name, fixture := range map[string]any{
		"credential": fullCredential("id", 1), "authorization": fullAuthorization("id", 1),
		"grant": fullGrant("id", 1), "deferred": fullDeferred("id", 1),
	} {
		if missing := unset(fixture); len(missing) > 0 {
			t.Errorf("%s fixture leaves %v unset", name, missing)
		}
	}
	c := fullCredential("id", 1)
	c.Copies[1].ShownTo = nil
	c.Display.Logo = nil
	if got := unset(c); !slices.Equal(got, []string{"Copies[1].ShownTo", "Display.Logo"}) {
		t.Errorf("unset = %v", got)
	}
}

// TestDiff: diff finds a dropped or changed field, and ignores what a
// faithful store may change — a time's location, a nil slice for an
// empty one, JSON's spacing.
func TestDiff(t *testing.T) {
	want := fullCredential("id", 1)
	same := fullCredential("id", 1)
	same.ReceivedAt = same.ReceivedAt.In(time.FixedZone("x", 3600))
	if d := diff(same, want); len(d) > 0 {
		t.Errorf("diff of an equal credential = %v", d)
	}
	dropped := fullCredential("id", 1)
	dropped.Copies[1].StatusList = nil
	dropped.Claims["address"].(map[string]any)["locality"] = "elsewhere"
	if d := diff(dropped, want); len(d) != 2 {
		t.Errorf("diff of a credential with two changes = %v", d)
	}
	if d := diff(walletflow.StoredCredential{Copies: []walletflow.CredentialCopy{}}, walletflow.StoredCredential{}); len(d) > 0 {
		t.Errorf("diff of an empty slice and nil = %v", d)
	}
	a := walletflow.PendingAuthorization{Session: json.RawMessage(`{"a": 1, "b": [true]}`)}
	b := walletflow.PendingAuthorization{Session: json.RawMessage(`{"b":[true],"a":1}`)}
	if d := diff(a, b); len(d) > 0 {
		t.Errorf("diff of equal JSON = %v", d)
	}
	b.Session = json.RawMessage(`{"a":2}`)
	if d := diff(a, b); len(d) != 1 {
		t.Errorf("diff of different JSON = %v", d)
	}
	g, w := fullGrant("id", 1), fullGrant("id", 2)
	if d := diff(g, w); len(d) != 7 {
		t.Errorf("diff of grants differing in every field but ID, ClientAuth and TokenType = %d differences, want 7: %v", len(d), d)
	}
}
