package issuerapp

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The kept-passport cap counts a request when it's reserved, so requests
// in flight count against it, and a reservation released after a failure
// gives its slot back.
func TestTransactions_KeptPassportCapCountsReservations(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tx := newTestTransactions(&now, 10)
	id, code, err := tx.put(passport.Evidence{}, testConfigIDs, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.claim(id, "", code); err != nil {
		t.Fatal(err)
	}
	for i := range maxIssuancesPerPassport {
		if _, _, err := tx.reserve(id, MdocConfigurationID); err != nil {
			t.Fatalf("reservation %d: %v", i+1, err)
		}
	}
	if _, _, err := tx.reserve(id, MdocConfigurationID); !errors.Is(err, errIssuanceLimit) {
		t.Fatalf("reservation past the cap with none finished: %v, want errIssuanceLimit", err)
	}
	tx.release(id, MdocConfigurationID)
	if _, _, err := tx.reserve(id, MdocConfigurationID); err != nil {
		t.Errorf("reservation after a release: %v, want its slot back", err)
	}
}

// Concurrent Credential Requests on one kept passport, each held between
// Prepare and done as the Credential Endpoint holds it while it signs,
// together stay within maxIssuancesPerPassport — and so within that many
// batches of status list indices.
func TestKeptPassportCap_HoldsUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	a, err := New(testConfig(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	d := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	e := passport.Evidence{
		Identity: passport.Identity{
			FamilyName: "DOE", GivenNames: "JANE", NamesFromMRZ: true,
			BirthDate: passport.BirthDate{Resolution: passport.BirthDateInferred, Date: d, Youngest: d},
			Sex:       "F", Nationality: "SGP", IssuingCountry: "SGP", DocumentNumber: "K0000000A",
			ExpiryDate: time.Now().AddDate(5, 0, 0),
		},
		File:   []byte("synthetic file"),
		Checks: passport.Checks{PassiveAuthentication: true, ChipAuthenticity: "n/a"},
	}
	offer, err := a.CreateOffer(ctx, e, OfferOptions{PreAuthorized: true, KeepForRefresh: true})
	if err != nil {
		t.Fatal(err)
	}
	grant := issuer.Grant{Subject: offer.IssuerState}
	signer := signerID(a.current().cert)
	before := len(a.IssuedStatuses())

	const inFlight, batch = maxIssuancesPerPassport + 30, 3
	var (
		wg       sync.WaitGroup
		ready    sync.WaitGroup
		accepted atomic.Int32
		finish   = make(chan struct{})
	)
	ready.Add(inFlight)
	for range inFlight {
		wg.Go(func() {
			req := &issuer.CredentialRequest{ResolvedConfigurationID: SDJWTConfigurationID}
			done, err := a.prepareCredential(ctx, grant, req, signer)
			if err != nil {
				ready.Done()
				return
			}
			instances := make([]*issuer.CredentialInstance, batch)
			for i := range instances {
				instances[i] = &issuer.CredentialInstance{Index: i, SDJWTClaims: &sdjwtvc.Claims{}}
			}
			if err := req.PerBatch(ctx, instances); err != nil {
				ready.Done()
				done(false)
				return
			}
			accepted.Add(1)
			ready.Done()
			<-finish
			done(true)
		})
	}
	ready.Wait()
	close(finish)
	wg.Wait()

	if got := int(accepted.Load()); got != maxIssuancesPerPassport {
		t.Errorf("concurrent requests accepted = %d, want the cap, %d", got, maxIssuancesPerPassport)
	}
	if got := len(a.IssuedStatuses()) - before; got != maxIssuancesPerPassport*batch {
		t.Errorf("status list indices allocated = %d, want %d", got, maxIssuancesPerPassport*batch)
	}
}
