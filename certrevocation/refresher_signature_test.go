package certrevocation_test

import (
	"context"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// TestRefresher_ForgedListRefusedUnparsed checks that a fetched list
// naming a configured issuer, but signed with another key, is refused
// before it's parsed: refusing a forged list of many entries costs a
// bounded number of allocations, not several per entry.
func TestRefresher_ForgedListRefusedUnparsed(t *testing.T) {
	p := newPKI(t)
	const entries = 20_000
	revoked := time.Now().Add(-time.Minute)
	tmpl := &x509.RevocationList{RevokedCertificateEntries: make([]x509.RevocationListEntry, entries)}
	for i := range tmpl.RevokedCertificateEntries {
		tmpl.RevokedCertificateEntries[i] = x509.RevocationListEntry{SerialNumber: new(big.Int).Lsh(big.NewInt(int64(i+1)), 64), RevocationTime: revoked}
	}
	forged := testcert.CRLFromTemplate(t, tmpl, p.fakeInter, p.fakeKey)
	tests := map[string]struct {
		bind bool
		want string
	}{
		"unbound URL": {false, "configured issuers"},
		"bound URL":   {true, "binds this URL to"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			srv := newCRLServer(t)
			u := srv.URL + "/ca.crl"
			cfg := certrevocation.RefresherConfig{URLs: []string{u}, Issuers: []*x509.Certificate{p.inter, p.otherCA}}
			if tc.bind {
				cfg.URLIssuers = map[string]*x509.Certificate{u: p.inter}
			}
			r := newRefresher(t, cfg)
			srv.serveCRL("/ca.crl", forged)
			var err error
			allocs := testing.AllocsPerRun(3, func() { err = r.Refresh(context.Background()) })
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Refresh = %v, want an error containing %q", err, tc.want)
			}
			// A fetch costs a few hundred allocations; parsing the list
			// would cost more than one per entry.
			if allocs > entries/10 {
				t.Errorf("refusing a forged list of %d entries took %.0f allocations: it was parsed before its signature was checked", entries, allocs)
			}
		})
	}
}
