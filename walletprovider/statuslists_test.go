package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// withPeriod sets a StatusListPeriod as long as the default Key
// Attestation TTL, the shortest it may be.
func withPeriod(c *walletprovider.Config, _ *walletprovider.Dependencies) {
	c.StatusListPeriod = walletprovider.DefaultKeyAttestationTTL
}

// TestStatusListRotation: an instance key used in a later period moves
// to that period's lists, keeping its index of the previous period, and
// only that one, as PreviousStatus; Wallet and Key Attestations name
// the current period's list.
func TestStatusListRotation(t *testing.T) {
	h := newHarness(t, withPeriod)
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	first := h.instanceKey(&key.PublicKey)
	if first.Status.URI != listURI(h.periodStart(), 0) || first.PreviousStatus != (statuslist.StatusListRef{}) || first.Revision != 1 {
		t.Fatalf("recorded %+v", first)
	}
	walletAttestation := func() statuslist.StatusListRef {
		t.Helper()
		jwt, err := h.walletAttestation(in.ID, &key.PublicKey, "")
		if err != nil {
			t.Fatal(err)
		}
		return walletAttestationStatus(t, jwt)
	}

	// The same period: the record stays as it is.
	h.clock.advance(time.Second)
	if ref := walletAttestation(); ref != first.Status || h.instanceKey(&key.PublicKey).Revision != 1 {
		t.Fatalf("within the period, status %+v and the record moved", ref)
	}

	// The next period: a fresh index there, the old one kept.
	h.toNextPeriod()
	ref := walletAttestation()
	moved := h.instanceKey(&key.PublicKey)
	if ref != moved.Status || moved.Status.URI != listURI(h.periodStart(), 0) || moved.PreviousStatus != first.Status || moved.Revision != 2 {
		t.Fatalf("after a period, status %+v, record %+v; want on %s, previous %+v", ref, moved, listURI(h.periodStart(), 0), first.Status)
	}
	h.expectStatus(statuslist.StatusValid, key)

	// Two periods on: nothing names the old indices any more.
	h.toNextPeriod()
	h.toNextPeriod()
	ref = walletAttestation()
	again := h.instanceKey(&key.PublicKey)
	if ref != again.Status || again.Status.URI != listURI(h.periodStart(), 0) || again.PreviousStatus != (statuslist.StatusListRef{}) {
		t.Fatalf("two periods on, status %+v, record %+v; want on %s, no previous", ref, again, listURI(h.periodStart(), 0))
	}

	// A Key Attestation moves the key too.
	h.toNextPeriod()
	holder := newKey(t)
	res, err := h.keyAttestation(in.ID, &key.PublicKey, []*ecdsa.PrivateKey{holder}, kindStrongBox)
	if err != nil {
		t.Fatal(err)
	}
	ka := h.instanceKey(&key.PublicKey)
	if ka.Status.URI != listURI(h.periodStart(), 0) || ka.PreviousStatus != again.Status {
		t.Fatalf("after a Key Attestation in a new period, record %+v", ka)
	}
	h.verifyKeyAttestation(res, ka.Status, &holder.PublicKey)
}

// TestTransitionSetsBothStatuses: Suspend, Resume and Revoke set an
// instance key's status at its Status and its PreviousStatus, and skip
// an index on a list no longer served.
func TestTransitionSetsBothStatuses(t *testing.T) {
	h := newHarness(t, withPeriod)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	moved := h.newInstanceKey(in.ID, kindStrongBox)
	stale := h.newInstanceKey(in.ID, kindStrongBox)
	staleRef := h.instanceKey(&stale.PublicKey).Status
	h.toNextPeriod()
	if _, err := h.walletAttestation(in.ID, &moved.PublicKey, ""); err != nil {
		t.Fatal(err)
	}
	if ik := h.instanceKey(&moved.PublicKey); ik.PreviousStatus.URI == "" {
		t.Fatalf("the key didn't move: %+v", ik)
	}
	for _, step := range []struct {
		do   func() error
		want statuslist.StatusType
	}{
		{func() error { return h.p.Suspend(ctx, in.ID, "lost") }, statuslist.StatusSuspended},
		{func() error { return h.p.Resume(ctx, in.ID) }, statuslist.StatusValid},
		{func() error { return h.p.Revoke(ctx, in.ID, "stolen") }, statuslist.StatusInvalid},
	} {
		if err := step.do(); err != nil {
			t.Fatal(err)
		}
		h.expectStatus(step.want, moved, stale)
	}

	// Three periods on, the unmoved key's list isn't served, and
	// setting statuses passes it by.
	h.toNextPeriod()
	h.toNextPeriod()
	if code, _ := h.getStatusList(strings.TrimPrefix(staleRef.URI, statusBase), ""); code != http.StatusNotFound {
		t.Fatalf("a list three periods old: %d, want 404", code)
	}
	if err := h.p.Revoke(ctx, in.ID, "again"); err != nil {
		t.Fatalf("revoking with a key on a list no longer served: %v", err)
	}
}

// TestConcurrentMovesOneRecord: concurrent requests for an instance key
// in a new period leave it one record, which every attestation names.
func TestConcurrentMovesOneRecord(t *testing.T) {
	h := newHarness(t, withPeriod)
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	before := h.instanceKey(&key.PublicKey)
	h.toNextPeriod()
	const workers = 8
	jwts := make([]string, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() {
			jwts[i], errs[i] = h.p.WalletAttestation(context.Background(), walletprovider.WalletAttestationRequest{
				InstanceID: in.ID, ClientID: clientID, InstanceKey: &key.PublicKey,
			})
		})
	}
	wg.Wait()
	after := h.instanceKey(&key.PublicKey)
	if after.Revision != 2 || after.PreviousStatus != before.Status || after.Status.URI != listURI(h.periodStart(), 0) {
		t.Fatalf("after concurrent moves: %+v", after)
	}
	for i := range workers {
		if errs[i] != nil {
			t.Fatalf("request %d: %v", i, errs[i])
		}
		if ref := walletAttestationStatus(t, jwts[i]); ref != after.Status {
			t.Fatalf("request %d: status %+v, want the record's %+v", i, ref, after.Status)
		}
	}
}

// TestLegacyInstanceKeysMove: an instance key whose Status isn't on a
// period's list — recorded before lists had periods, or under another
// StatusListPeriod — moves to the current period's lists, with no
// previous index to keep.
func TestLegacyInstanceKeysMove(t *testing.T) {
	h := newHarness(t, withPeriod)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	for _, uri := range []string{
		statusBase,
		statusBase + "/" + strconv.FormatInt(h.periodStart()+1, 10) + "/0",
		statusBase + "/" + strconv.FormatInt(h.periodStart(), 10) + "/64",
		statusBase + "/" + strconv.FormatInt(h.periodStart(), 10) + "/00",
		"https://elsewhere.example/status/" + strconv.FormatInt(h.periodStart(), 10) + "/0",
	} {
		key := h.newInstanceKey(in.ID, kindStrongBox)
		ik := h.instanceKey(&key.PublicKey)
		ik.Status = statuslist.StatusListRef{Idx: 5, URI: uri}
		if err := h.deps.InstanceKeys.Update(ctx, ik); err != nil {
			t.Fatal(err)
		}
		jwt, err := h.walletAttestation(in.ID, &key.PublicKey, "")
		if err != nil {
			t.Fatal(err)
		}
		moved := h.instanceKey(&key.PublicKey)
		if ref := walletAttestationStatus(t, jwt); ref != moved.Status || moved.Status.URI != listURI(h.periodStart(), 0) || moved.PreviousStatus != (statuslist.StatusListRef{}) {
			t.Fatalf("a key on %s: status %+v, record %+v", uri, ref, moved)
		}
	}
}

// TestStatusListsServed: StatusLists serves the lists of the periods
// from two before the current one to the next that have an index handed
// out, and nothing else.
func TestStatusListsServed(t *testing.T) {
	h := newHarness(t, withPeriod)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	h.newInstanceKey(in.ID, kindStrongBox)
	start := h.periodStart()
	period := int64(h.period() / time.Second)
	reserve := func(s int64) {
		t.Helper()
		if err := h.deps.StatusIndices.Reserve(ctx, listURI(s, 0), 1); err != nil {
			t.Fatal(err)
		}
	}
	reserve(start + period)
	reserve(start + 2*period)
	reserve(start - 2*period)
	reserve(start - 3*period)

	path := func(s int64, n string) string { return "/" + strconv.FormatInt(s, 10) + "/" + n }
	for _, tc := range []struct {
		name, path string
		want       int
	}{
		{"current", path(start, "0"), http.StatusOK},
		{"next period", path(start+period, "0"), http.StatusOK},
		{"two periods before", path(start-2*period, "0"), http.StatusOK},
		{"two periods on", path(start+2*period, "0"), http.StatusNotFound},
		{"three periods before", path(start-3*period, "0"), http.StatusNotFound},
		{"no index handed out", path(start, "1"), http.StatusNotFound},
		{"last list, empty", path(start, "63"), http.StatusNotFound},
		{"past the last list", path(start, "64"), http.StatusNotFound},
		{"negative list", path(start, "-1"), http.StatusNotFound},
		{"leading zero", path(start, "00"), http.StatusNotFound},
		{"signed", path(start, "+0"), http.StatusNotFound},
		{"start unaligned", path(start+1, "0"), http.StatusNotFound},
		{"start not a number", "/now/0", http.StatusNotFound},
		{"start with a leading zero", "/0" + strconv.FormatInt(start, 10) + "/0", http.StatusNotFound},
		{"more segments", path(start, "0/1"), http.StatusNotFound},
		{"the base itself", "/", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := h.getStatusList(tc.path, "")
			if code != tc.want {
				t.Fatalf("GET %s: %d %s, want %d", tc.path, code, body, tc.want)
			}
		})
	}

	req := httptest.NewRequest(http.MethodGet, path(start, "0"), nil)
	rec := httptest.NewRecorder()
	h.p.StatusLists().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != statuslist.TokenMediaType {
		t.Fatalf("GET a list without Accept: %d %s, want the JWT", rec.Code, rec.Header().Get("Content-Type"))
	}

	// Handler serves them under StatusPath, and nothing at StatusPath
	// itself.
	ts := httptest.NewServer(h.p.Handler())
	t.Cleanup(ts.Close)
	for p, want := range map[string]int{
		walletprovider.StatusPath + path(start, "0"): http.StatusOK,
		walletprovider.StatusPath:                    http.StatusNotFound,
		walletprovider.StatusPath + "/":              http.StatusNotFound,
	} {
		resp, err := ts.Client().Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("GET %s through Handler: %d, want %d", p, resp.StatusCode, want)
		}
	}
}
