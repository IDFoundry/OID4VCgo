package walletflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testhaip"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// receive has w receive configIDs through the authorization code grant.
func receive(t *testing.T, f fixture, w *walletflow.Wallet, configIDs ...string) []walletflow.StoredCredential {
	t.Helper()
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, configIDs...))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return result.Credentials
}

func presentationFixture(t *testing.T) (fixture, *testhaip.Verifier, *walletflow.Wallet) {
	t.Helper()
	f := newFixture(t, testhaip.Options{})
	v := f.env.StartVerifier(t)
	return f, v, f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
}

func TestPresentation_SDJWT(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, testhaip.SDJWTConfigurationID, testhaip.MdocConfigurationID)
	ctx := context.Background()
	id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})

	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Verifier(); got.Name != v.Name || got.ClientID == "" || got.ResponseURI == "" {
		t.Errorf("Verifier = %+v", got)
	}
	candidates := p.Candidates()
	if len(candidates) != 1 || candidates[0].QueryID != "pid" || len(candidates[0].Credentials) != 1 || candidates[0].Credentials[0].ID != held[0].ID {
		t.Fatalf("Candidates = %+v", candidates)
	}
	disclosed, err := p.Preview(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(disclosed) != 1 || disclosed[0].CredentialID != held[0].ID || len(disclosed[0].Claims) != 1 || disclosed[0].Claims[0][0].Key() != "given_name" {
		t.Fatalf("Preview = %+v", disclosed)
	}
	presented, err := p.Respond(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(presented.QueryIDs) != 1 || presented.QueryIDs[0] != "pid" {
		t.Errorf("Presented = %+v", presented)
	}
	view := v.Lookup(t, id)
	if view.Status != verifier.TransactionDone || view.Result.Credentials[0].Claims["given_name"] != testhaip.GivenName {
		t.Fatalf("verifier = %+v", view)
	}
	if _, ok := view.Result.Credentials[0].Claims["family_name"]; ok {
		t.Error("family_name was disclosed, unasked")
	}
	if _, err := p.Respond(ctx, nil); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Respond twice = %v, want ErrWrongStep", err)
	}
	if _, err := p.Decline(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Decline after Respond = %v, want ErrWrongStep", err)
	}
}

func TestPresentation_ChoosesAmongCandidates(t *testing.T) {
	f, v, w := presentationFixture(t)
	first := receive(t, f, w, testhaip.MdocConfigurationID)
	second := receive(t, f, w, testhaip.MdocConfigurationID)
	ctx := context.Background()
	id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{testhaip.MdocQuery(t, "mdl", "family_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if c := p.Candidates(); len(c) != 1 || len(c[0].Credentials) != 2 || c[0].Credentials[0].ID != first[0].ID && c[0].Credentials[1].ID != first[0].ID {
		t.Fatalf("Candidates = %+v", c)
	}
	chosen := []string{second[0].ID}
	disclosed, err := p.Preview(ctx, chosen)
	if err != nil || len(disclosed) != 1 || disclosed[0].CredentialID != second[0].ID {
		t.Fatalf("Preview = %+v, %v", disclosed, err)
	}
	if _, err := p.Respond(ctx, []string{"no-such-credential"}); err == nil {
		t.Fatal("Respond with a credential that isn't a candidate succeeded")
	}
	if _, err := p.Respond(ctx, chosen); err != nil {
		t.Fatal(err)
	}
	if view := v.Lookup(t, id); view.Status != verifier.TransactionDone {
		t.Fatalf("verifier = %+v", view)
	}
}

func TestPresentation_NoMatchThenDecline(t *testing.T) {
	f, v, w := presentationFixture(t)
	receive(t, f, w, testhaip.SDJWTConfigurationID)
	ctx := context.Background()
	id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{testhaip.MdocQuery(t, "mdl", "family_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if c := p.Candidates(); len(c) != 0 {
		t.Fatalf("Candidates = %+v, want none", c)
	}
	if _, err := p.Preview(ctx, nil); !errors.Is(err, walletflow.ErrNoMatchingCredential) {
		t.Errorf("Preview = %v, want ErrNoMatchingCredential", err)
	}
	if _, err := p.Respond(ctx, nil); !errors.Is(err, walletflow.ErrNoMatchingCredential) {
		t.Errorf("Respond = %v, want ErrNoMatchingCredential", err)
	}
	// verifier.Transactions records a wallet's error response, leaving
	// the request pending (anyone holding its public key could send
	// one), and answers it with 400.
	var rejected *wallet.DirectPostRejectedError
	if _, err := p.Decline(ctx); err != nil && !errors.As(err, &rejected) {
		t.Fatal(err)
	}
	if view := v.Lookup(t, id); view.LastError != "the wallet returned an error: access_denied" {
		t.Errorf("verifier after Decline = %+v", view)
	}
	if _, err := p.Decline(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Decline twice = %v, want ErrWrongStep", err)
	}
}

func TestPresentation_RefusesAnUntrustedVerifier(t *testing.T) {
	f, _, w := presentationFixture(t)
	other := f.env.StartVerifier(t)
	_, link := other.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	if _, err := w.StartPresentation(context.Background(), link); err == nil {
		t.Fatal("a request from an untrusted Verifier was accepted")
	}
	noTrust := f.newWallet(t, f.env.IssuerRoots)
	if _, err := noTrust.StartPresentation(context.Background(), link); err == nil {
		t.Fatal("StartPresentation without VerifierTrust succeeded")
	}
}

func TestPresentation_MissingHolderKey(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, testhaip.SDJWTConfigurationID)
	ctx := context.Background()
	if err := f.keys.DeleteKey(ctx, held[0].HolderKeyID); err != nil {
		t.Fatal(err)
	}
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Respond(ctx, nil); !errors.Is(err, walletflow.ErrNotFound) {
		t.Fatalf("Respond without the holder key = %v, want ErrNotFound", err)
	}
}
