package walletflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// An authorization keeps the kind of credential each offered
// configuration issued when it began, which the holder was shown:
// resumed after a relaunch, when the issuer's configuration now issues
// another kind, it's refused (ErrReissueRequired) and forgotten, with
// its keys, as a deferred credential polled after a restart is.
func TestResumeIssuance_RefusesAnotherTypeThanShown(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	auth := walletflow.NewMemoryAuthorizationStore()
	redirect := beginThenQuit(t, f, auth)
	kept, err := auth.ListAuthorizations(ctx)
	if err != nil || len(kept) != 1 {
		t.Fatalf("authorizations = %+v, %v", kept, err)
	}
	types := kept[0].OfferedTypes
	if len(types) != 1 || types[0].ConfigurationID != walletflowtest.SDJWTConfigurationID || types[0].Format != "dc+sd-jwt" || types[0].VCT == "" {
		t.Fatalf("OfferedTypes = %+v, want the offered configuration's type", types)
	}
	// As if the holder had been shown another type: the issuer's
	// metadata maps the configuration to its PID's now.
	kept[0].OfferedTypes[0].VCT = "https://vct.example/coffee-loyalty-card"
	if err := auth.PutAuthorization(ctx, kept[0]); err != nil {
		t.Fatal(err)
	}
	relaunched := f.newWalletAuthorizing(t, auth, nil)
	if s, err := relaunched.ResumeIssuance(ctx, redirect); s != nil || !errors.Is(err, walletflow.ErrReissueRequired) {
		t.Fatalf("ResumeIssuance = (an issuance: %t), %v; want ErrReissueRequired", s != nil, err)
	}
	if left, _ := auth.ListAuthorizations(ctx); len(left) != 0 {
		t.Errorf("%d authorizations kept, want it forgotten", len(left))
	}
	if f.keys.Len() != 0 {
		t.Errorf("keys held = %d, want the authorization's forgotten with it", f.keys.Len())
	}
	if held, _ := relaunched.Credentials(ctx); len(held) != 0 {
		t.Errorf("credentials = %d, want none", len(held))
	}
}

// An authorization stored before the offered types were kept has none
// to hold to, and resumes as before.
func TestResumeIssuance_WithoutOfferedTypes(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	auth := walletflow.NewMemoryAuthorizationStore()
	redirect := beginThenQuit(t, f, auth)
	kept, err := auth.ListAuthorizations(ctx)
	if err != nil || len(kept) != 1 {
		t.Fatalf("authorizations = %+v, %v", kept, err)
	}
	kept[0].OfferedTypes = nil
	if err := auth.PutAuthorization(ctx, kept[0]); err != nil {
		t.Fatal(err)
	}
	s, err := f.newWalletAuthorizing(t, auth, nil).ResumeIssuance(ctx, redirect)
	if err != nil {
		t.Fatalf("ResumeIssuance = %v", err)
	}
	defer func() { _ = s.Close(ctx) }()
	if result, err := s.RequestCredentials(ctx); err != nil || len(result.Credentials) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
}
