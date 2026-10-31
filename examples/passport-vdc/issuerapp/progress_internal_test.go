package issuerapp

import (
	"testing"
	"time"
)

// An offer's coarse state follows its credentials first, then the
// approval step, then whether it's still held.
func TestOfferProgress_State(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	later, earlier := now.Add(time.Minute), now.Add(-time.Minute)
	creds := func(mdoc, sdjwt string) map[string]string {
		return map[string]string{"mso_mdoc": mdoc, "dc+sd-jwt": sdjwt}
	}
	for _, tc := range []struct {
		name string
		p    offerProgress
		held bool
		want string
	}{
		{"new", offerProgress{credentials: creds(credentialPending, credentialPending), offerExpires: later}, true, offerWaiting},
		{"declined", offerProgress{declined: true, credentials: creds(credentialPending, credentialPending), offerExpires: later}, true, offerDenied},
		{"approved", offerProgress{authorized: true, credentials: creds(credentialPending, credentialPending), offerExpires: later}, true, offerAuthorized},
		{"one issued", offerProgress{authorized: true, credentials: creds(credentialIssued, credentialPending), offerExpires: later}, true, offerAuthorized},
		{"issued", offerProgress{authorized: true, credentials: creds(credentialIssued, credentialIssued)}, false, offerIssued},
		{"deferred", offerProgress{authorized: true, credentials: creds(credentialDeferred, credentialApproved)}, false, offerDeferred},
		{"one refused", offerProgress{authorized: true, credentials: creds(credentialIssued, credentialRefused)}, false, offerIssued},
		{"refused", offerProgress{authorized: true, credentials: creds(credentialRefused, credentialRefused)}, false, offerRefused},
		{"expired", offerProgress{credentials: creds(credentialPending, credentialPending), offerExpires: earlier}, true, offerExpired},
		{"voided", offerProgress{declined: true, credentials: creds(credentialPending, credentialPending), offerExpires: later}, false, offerExpired},
	} {
		if got := tc.p.state(now, tc.held); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The steps name each credential and how it's doing, and the approval
// step by the grant: an approval, or a PIN.
func TestOfferProgress_Steps(t *testing.T) {
	p := offerProgress{
		preAuthorized: true, authorized: true, formats: []string{"mso_mdoc", "dc+sd-jwt"},
		credentials: map[string]string{"mso_mdoc": credentialIssued, "dc+sd-jwt": credentialIssued},
	}
	st := p.status(time.Now(), false)
	want := []progressStep{
		{"The wallet took the offer", "done"}, {"PIN accepted", "done"}, {"Credentials issued (mdoc ✓, SD-JWT VC ✓)", "done"},
	}
	if len(st.Steps) != len(want) {
		t.Fatalf("steps = %v", st.Steps)
	}
	for i := range want {
		if st.Steps[i] != want[i] {
			t.Errorf("step %d = %v, want %v", i, st.Steps[i], want[i])
		}
	}
	if !st.Final || st.Summary != "Credentials issued." {
		t.Errorf("status = %+v", st)
	}
}

// Only the browser that uploaded the passport reads its progress.
func TestProgressBoard_Binding(t *testing.T) {
	now := time.Now()
	b := newProgressBoard()
	id, err := b.add(now, "tx", "browser-a", false, []string{MdocConfigurationID}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.snapshot(now, id, "browser-a"); !ok {
		t.Error("the uploading browser can't read its offer's progress")
	}
	for _, browser := range []string{"browser-b", ""} {
		if _, ok := b.snapshot(now, id, browser); ok {
			t.Errorf("browser %q reads another browser's progress", browser)
		}
	}
	if _, ok := b.snapshot(now.Add(time.Minute+progressMargin), id, "browser-a"); ok {
		t.Error("progress is kept past its lifetime")
	}
}
