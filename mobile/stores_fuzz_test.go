package mobile

import (
	"bytes"
	"context"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// FuzzStoredRecords reads arbitrary records back from the app's
// CredentialStore, as the walletflow store adapters do: a record is the
// app's bytes, which a bug, a migration or another process may have
// changed. Nothing panics. A credential decodes only under its own ID,
// and re-encodes to a record that decodes to the same credential. An
// Update (CompareAndSwap) that fails leaves the record as it was; one
// that changes nothing writes the credential's own encoding. Consuming
// an authorization deletes its record only when it decodes for that
// state, and otherwise leaves it. Listing yields no credential twice.
func FuzzStoredRecords(f *testing.F) {
	f.Add([]byte(`{"id":"b","format":"dc+sd-jwt","credential":"x","holder_key_id":"kb","received_at":"2026-10-01T00:00:00Z"}`), "b", "s")
	f.Add([]byte(`{"id":"b","format":"mso_mdoc","credential":"x","holder_key_id":"kb","received_at":"2026-10-01T00:00:00+02:00",`+
		`"copies":[{"credential":"y","holder_key_id":"k2","presented":true,"shown_to":["v"],"status_list":{"idx":1,"uri":"https://s"}}],`+
		`"valid_until":"2027-01-01T00:00:00Z","status_list":{"idx":3,"uri":"https://s"},"status":{"status":"valid"},"claims":{"a":1}}`), "b", "s")
	f.Add([]byte(`{"kind":"authorization","state":"s","session":{},"expires_at":"2026-10-01T00:00:00Z"}`), "a", "s")
	f.Add([]byte(`{"kind":"authorization","state":"t","session":{}}`), "a", "s")
	f.Add([]byte(`{"kind":"deferred","id":"d","holder_key_id":"k","interval_seconds":1e300}`), "d", "s")
	f.Add([]byte(`{"id":"c"}`), "b", "s")
	f.Add([]byte(`[]`), "", "")
	f.Fuzz(func(t *testing.T, record []byte, id, state string) {
		ctx := context.Background()
		m := memStore{records: map[string][]byte{id: record, "other": record}}
		cs, ds, as, gs := credentialStore{m}, deferredStore{m}, authorizationStore{m}, grantStore{m}

		if c, err := decodeCredential(id, record); err == nil {
			checkCredentialReencodes(t, id, c)
		}
		before := bytes.Clone(m.records[id])
		if err := cs.Update(ctx, id, func(*walletflow.StoredCredential) error { return nil }); err != nil {
			if !bytes.Equal(m.records[id], before) {
				t.Fatalf("a failed Update changed %q's record from %q to %q", id, before, m.records[id])
			}
		} else if c, err := decodeCredential(id, before); err != nil {
			t.Fatalf("Update accepted %q, which doesn't decode: %v", before, err)
		} else if enc, _ := encodeCredential(c); !bytes.Equal(m.records[id], enc) {
			t.Fatalf("an Update changing nothing wrote %q, not %q", m.records[id], enc)
		}

		if list, err := cs.List(ctx); err == nil {
			seen := map[string]bool{}
			for _, c := range list {
				if c.ID == "" || seen[c.ID] {
					t.Fatalf("List yielded credential %q twice, or without an ID", c.ID)
				}
				seen[c.ID] = true
			}
		}
		_, _ = ds.ListDeferred(ctx)
		_, _ = as.ListAuthorizations(ctx)
		_, _ = gs.ListGrants(ctx)

		key := authorizationStoreID(state)
		m.records[key] = record
		a, err := as.ConsumeAuthorization(ctx, state)
		_, kept := m.records[key]
		switch {
		case err != nil && (!kept || !bytes.Equal(m.records[key], record)):
			t.Fatalf("a refused ConsumeAuthorization(%q) changed its record %q", state, record)
		case err == nil && (kept || a.State != state):
			t.Fatalf("ConsumeAuthorization(%q) = state %q, record kept: %v", state, a.State, kept)
		}
	})
}

// checkCredentialReencodes fails t unless c, decoded as credential id,
// encodes to a record that decodes again as id to a credential that
// encodes the same.
func checkCredentialReencodes(t *testing.T, id string, c walletflow.StoredCredential) {
	t.Helper()
	if c.ID != id {
		t.Fatalf("the record for %q decoded as credential %q", id, c.ID)
	}
	enc, err := encodeCredential(c)
	if err != nil {
		t.Fatalf("a decoded credential doesn't encode: %v", err)
	}
	again, err := decodeCredential(id, enc)
	if err != nil {
		t.Fatalf("a credential's own record %q doesn't decode: %v", enc, err)
	}
	if enc2, err := encodeCredential(again); err != nil || !bytes.Equal(enc, enc2) {
		t.Fatalf("a credential's record changed on a round trip: %q, then %q (%v)", enc, enc2, err)
	}
}
