package walletflow_test

import (
	"context"
	"crypto/x509"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// The issuer's display metadata reaches the offer and the stored
// credential, in the holder's language.
func TestDisplay(t *testing.T) {
	for locales, want := range map[string]string{"": walletflowtest.SDJWTName, "de-CH": walletflowtest.SDJWTNameDE} {
		f := newFixture(t, walletflowtest.Options{})
		var prefs []string
		if locales != "" {
			prefs = []string{locales}
		}
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
			Development: true, Locales: prefs,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
		if err != nil {
			t.Fatal(err)
		}
		o := s.Offer()
		oc := o.Credentials[0]
		if o.IssuerName != walletflowtest.IssuerName || o.IssuerLogo == nil || o.IssuerLogo.AltText != walletflowtest.LogoAltText ||
			oc.Name != want || oc.Description != walletflowtest.Description ||
			oc.BackgroundColor != walletflowtest.BackgroundColor || oc.TextColor != walletflowtest.TextColor || oc.Logo == nil {
			t.Errorf("locales %q: offer = %+v, %+v", locales, o, oc)
		}
		authorize(t, f, s)
		result, err := s.RequestCredentials(ctx)
		if err != nil {
			t.Fatal(err)
		}
		_ = s.Close(ctx)
		d := result.Credentials[0].Display
		if d.Name != want || d.IssuerName != walletflowtest.IssuerName || d.Logo == nil {
			t.Errorf("locales %q: stored display = %+v", locales, d)
		}
	}
}

// A received credential keeps its expiry and status reference;
// CheckStatus reads the issuer's status list, and sees a revocation
// once the list it kept has expired.
func TestCheckStatus(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	var mu sync.Mutex
	now := time.Now()
	f.w = f.newWalletAuthorizing(t, nil, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	held := receive(t, f, f.w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	ctx := context.Background()
	for _, c := range held {
		if c.ValidUntil.Before(time.Now()) || c.StatusList == nil || c.StatusListCWT != (c.Format == "mso_mdoc") {
			t.Fatalf("%s: valid until %v, status list %+v (CWT %v)", c.Format, c.ValidUntil, c.StatusList, c.StatusListCWT)
		}
		checked, err := f.w.CheckStatus(ctx, c.ID)
		if err != nil || checked.Status.Value != walletflow.StatusValid || checked.Status.CheckedAt.IsZero() {
			t.Fatalf("%s: CheckStatus = %+v, %v", c.Format, checked.Status, err)
		}
	}
	f.env.Revoke()
	for _, c := range held {
		checked, err := f.w.CheckStatus(ctx, c.ID)
		if err != nil || checked.Status.Value != walletflow.StatusValid {
			t.Errorf("%s after Revoke, the list kept: %+v, %v", c.Format, checked.Status, err)
		}
	}
	mu.Lock()
	now = now.Add(statuslist.DefaultCacheMaxAge)
	mu.Unlock()
	for _, c := range held {
		checked, err := f.w.CheckStatus(ctx, c.ID)
		if err != nil || checked.Status.Value != walletflow.StatusInvalid {
			t.Errorf("%s after Revoke: %+v, %v", c.Format, checked.Status, err)
		}
		if stored, _ := f.store.Get(ctx, c.ID); stored.Status.Value != walletflow.StatusInvalid {
			t.Errorf("%s: the status isn't stored: %+v", c.Format, stored.Status)
		}
	}
}

// A credential whose iss its certificate doesn't name, as the EU
// reference PID's doesn't, is received, and its status list, signed
// with the same key, is its issuer's: CheckStatus reads it. Its iss
// isn't the credential_issuer either, which the wallet allows.
func TestCheckStatus_IssNotNamedByTheCertificate(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{SDJWTIss: "https://backend.issuer.example"})
	f.w = foreignIssWallet(t, f)
	held := receive(t, f, f.w, walletflowtest.SDJWTConfigurationID)
	c := held[0]
	if c.Claims["iss"] != "https://backend.issuer.example" {
		t.Fatalf("iss = %v", c.Claims["iss"])
	}
	checked, err := f.w.CheckStatus(context.Background(), c.ID)
	if err != nil || checked.Status.Value != walletflow.StatusValid {
		t.Fatalf("CheckStatus = %+v, %v", checked.Status, err)
	}
}

// An expired credential isn't valid whatever its status says, so
// CheckStatus doesn't fetch its status list (draft-ietf-oauth-status-list
// §8.3): a revocation since isn't seen, and nothing is recorded.
func TestCheckStatus_SkipsAnExpiredCredential(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	c := receive(t, f, f.w, walletflowtest.SDJWTConfigurationID)[0]
	ctx := context.Background()
	c.ValidUntil = time.Now().Add(-time.Minute)
	for i := range c.Copies {
		c.Copies[i].ValidUntil = c.ValidUntil
	}
	if err := f.store.Put(ctx, c); err != nil {
		t.Fatal(err)
	}
	f.env.Revoke()
	checked, err := f.w.CheckStatus(ctx, c.ID)
	if err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}
	if checked.Status.Value != "" || !checked.Status.CheckedAt.IsZero() {
		t.Errorf("Status = %+v, want none: the list wasn't to be fetched", checked.Status)
	}
}

// With signed issuer metadata required, an issuer whose metadata isn't
// signed under IssuerMetadataRoots is refused at StartIssuance, before
// the holder signs in or enters a code (HAIP 1.0 §4.1; OpenID4VCI
// §13.6.2). Without the requirement it's used as before.
func TestStartIssuance_RequireSignedIssuerMetadata(t *testing.T) {
	for _, require := range []bool{true, false} {
		f := newFixture(t, walletflowtest.Options{})
		other, _ := testcert.CA(t, "another metadata root")
		roots := x509.NewCertPool()
		roots.AddCert(other)
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots, Development: true,
			IssuerMetadataRoots: roots, RequireSignedIssuerMetadata: require,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		_, err = w.StartIssuance(context.Background(), f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
		if require && err == nil {
			t.Error("required: started an issuance with an issuer whose metadata isn't signed under the roots")
		}
		if !require && err != nil {
			t.Errorf("not required: %v", err)
		}
	}
}

// Each copy of a batch has its own status list entry (HAIP 1.0 §6.1):
// CheckStatus checks them all, and reports a copy's revocation even
// while the others are valid. A copy that has expired isn't checked.
func TestCheckStatus_EveryCopy(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	c := receive(t, f, f.w, walletflowtest.SDJWTConfigurationID)[0]
	ctx := context.Background()
	if len(c.Copies) != 3 {
		t.Fatalf("copies = %d, want 3", len(c.Copies))
	}
	seen := map[uint64]bool{}
	for i, cp := range c.Copies {
		if cp.StatusList == nil || cp.ValidUntil.IsZero() || seen[cp.StatusList.Idx] {
			t.Fatalf("copy %d: status %v, valid until %v; want its own entry and expiry", i, cp.StatusList, cp.ValidUntil)
		}
		seen[cp.StatusList.Idx] = true
		if c.ValidUntil.After(cp.ValidUntil) {
			t.Errorf("ValidUntil %v is after copy %d's %v", c.ValidUntil, i, cp.ValidUntil)
		}
	}
	f.env.RevokeEntry(c.Copies[2].StatusList.Idx)
	checked, err := f.w.CheckStatus(ctx, c.ID)
	if err != nil || checked.Status.Value != walletflow.StatusInvalid {
		t.Fatalf("one copy revoked: CheckStatus = %+v, %v; want invalid", checked.Status, err)
	}

	checked.Copies[2].ValidUntil = time.Now().Add(-time.Minute)
	if err := f.store.Put(ctx, checked); err != nil {
		t.Fatal(err)
	}
	if checked, err = f.w.CheckStatus(ctx, c.ID); err != nil || checked.Status.Value != walletflow.StatusValid {
		t.Errorf("the revoked copy expired: CheckStatus = %+v, %v; want valid", checked.Status, err)
	}
}
