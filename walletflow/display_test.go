package walletflow_test

import (
	"context"
	"testing"
	"time"

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
// CheckStatus reads the issuer's status list, and sees a revocation.
func TestCheckStatus(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
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
		if err != nil || checked.Status.Value != walletflow.StatusInvalid {
			t.Errorf("%s after Revoke: %+v, %v", c.Format, checked.Status, err)
		}
		if stored, _ := f.store.Get(ctx, c.ID); stored.Status.Value != walletflow.StatusInvalid {
			t.Errorf("%s: the status isn't stored: %+v", c.Format, stored.Status)
		}
	}
}
