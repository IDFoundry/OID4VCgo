package walletflow_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
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

func presentationFixture(t *testing.T) (fixture, testVerifier, *walletflow.Wallet) {
	t.Helper()
	f := newFixture(t, walletflowtest.Options{})
	v := f.env.StartVerifier(t)
	return f, v, f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
}

func TestPresentation_SDJWT(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	ctx := context.Background()
	id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})

	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Verifier(); got.Name != v.Name || got.ClientID == "" || got.ResponseURI == "" {
		t.Errorf("Verifier = %+v", got)
	}
	queries := p.Queries()
	if len(queries) != 1 || queries[0].ID != "pid" || queries[0].Multiple || len(queries[0].Credentials) != 1 || queries[0].Credentials[0].ID != held[0].ID {
		t.Fatalf("Queries = %+v", queries)
	}
	sel, err := p.DefaultSelection(ctx)
	if err != nil || len(sel["pid"]) != 1 || sel["pid"][0] != held[0].ID {
		t.Fatalf("DefaultSelection = %v, %v", sel, err)
	}
	disclosed, err := p.Preview(ctx, sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(disclosed) != 1 || disclosed[0].CredentialID != held[0].ID || len(disclosed[0].Claims) != 1 || disclosed[0].Claims[0][0].Key() != "given_name" {
		t.Fatalf("Preview = %+v", disclosed)
	}
	presented, err := p.Respond(ctx, sel)
	if err != nil {
		t.Fatal(err)
	}
	if len(presented.QueryIDs) != 1 || presented.QueryIDs[0] != "pid" {
		t.Errorf("Presented = %+v", presented)
	}
	view := v.Lookup(t, id)
	if view.Status != verifier.TransactionDone || view.Result.Credentials[0].Claims["given_name"] != walletflowtest.GivenName {
		t.Fatalf("verifier = %+v", view)
	}
	if _, ok := view.Result.Credentials[0].Claims["family_name"]; ok {
		t.Error("family_name was disclosed, unasked")
	}
	if _, err := p.Respond(ctx, sel); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Respond twice = %v, want ErrWrongStep", err)
	}
	if _, err := p.Decline(ctx); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("Decline after Respond = %v, want ErrWrongStep", err)
	}
}

func TestPresentation_ChoosesAmongCandidates(t *testing.T) {
	f, v, w := presentationFixture(t)
	first := receive(t, f, w, walletflowtest.MdocConfigurationID)
	second := receive(t, f, w, walletflowtest.MdocConfigurationID)
	ctx := context.Background()
	id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{mdocQuery(t, "mdl", "family_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if q := p.Queries(); len(q) != 1 || len(q[0].Credentials) != 2 || q[0].Credentials[0].ID != first[0].ID && q[0].Credentials[1].ID != first[0].ID {
		t.Fatalf("Queries = %+v", q)
	}
	chosen := walletflow.Selection{"mdl": {second[0].ID}}
	disclosed, err := p.Preview(ctx, chosen)
	if err != nil || len(disclosed) != 1 || disclosed[0].CredentialID != second[0].ID {
		t.Fatalf("Preview = %+v, %v", disclosed, err)
	}
	for name, bad := range map[string]walletflow.Selection{
		"an unknown credential":          {"mdl": {"no-such-credential"}},
		"an unknown query":               {"pid": {second[0].ID}},
		"two for a query that takes one": {"mdl": {first[0].ID, second[0].ID}},
		"nothing":                        {},
	} {
		if _, err := p.Respond(ctx, bad); !errors.Is(err, walletflow.ErrInvalidSelection) {
			t.Errorf("Respond with %s = %v, want ErrInvalidSelection", name, err)
		}
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
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{mdocQuery(t, "mdl", "family_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if q := p.Queries(); len(q) != 1 || len(q[0].Credentials) != 0 {
		t.Fatalf("Queries = %+v, want the query, with nothing that answers it", q)
	}
	if _, err := p.DefaultSelection(ctx); !errors.Is(err, walletflow.ErrNoMatchingCredential) {
		t.Errorf("DefaultSelection = %v, want ErrNoMatchingCredential", err)
	}
	// verifier.Transactions answers the error response with 200, and
	// records it, leaving the request pending: anyone holding its public
	// key could send one.
	if _, err := p.Decline(ctx); err != nil {
		t.Fatalf("Decline = %v", err)
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
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	if err := f.keys.DeleteKey(ctx, held[0].HolderKeyID); err != nil {
		t.Fatal(err)
	}
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Respond(ctx, walletflow.Selection{"pid": {held[0].ID}}); !errors.Is(err, walletflow.ErrNotFound) {
		t.Fatalf("Respond without the holder key = %v, want ErrNotFound", err)
	}
}

// TestPresentation_CredentialSetOptions: a request that takes either
// format lists the candidates for both, and the holder's choice decides
// which option is answered.
func TestPresentation_CredentialSetOptions(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, walletflowtest.MdocConfigurationID, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	query := dcql.Query{
		Credentials:    []dcql.CredentialQuery{mdocQuery(t, "mdl", "family_name"), f.env.SDJWTQuery(t, "pid", "family_name")},
		CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"mdl"}, {"pid"}}}},
	}
	id, link := v.Begin(t, query)
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if q := p.Queries(); len(q) != 2 || q[0].ID != "mdl" || q[1].ID != "pid" {
		t.Fatalf("Queries = %+v, want both options' queries", q)
	}
	if sets := p.CredentialSets(); len(sets) != 1 || !sets[0].Required || len(sets[0].Options) != 2 {
		t.Fatalf("CredentialSets = %+v", sets)
	}
	var sdjwt string
	for _, c := range held {
		if c.Format == "dc+sd-jwt" {
			sdjwt = c.ID
		}
	}
	var mdl string
	for _, c := range held {
		if c.Format == "mso_mdoc" {
			mdl = c.ID
		}
	}
	// Answering both options isn't one option: a stray query.
	if _, err := p.Preview(ctx, walletflow.Selection{"mdl": {mdl}, "pid": {sdjwt}}); err != nil {
		t.Errorf("both options answered: %v (each is a complete option, so it's allowed)", err)
	}
	presented, err := p.Respond(ctx, walletflow.Selection{"pid": {sdjwt}})
	if err != nil {
		t.Fatal(err)
	}
	if len(presented.QueryIDs) != 1 || presented.QueryIDs[0] != "pid" {
		t.Fatalf("Presented = %+v, want the SD-JWT VC option", presented)
	}
	if view := v.Lookup(t, id); view.Status != verifier.TransactionDone {
		t.Fatalf("verifier = %+v", view)
	}
}

// Without credential_sets every query is required: a Selection leaving
// one out is refused, naming it.
func TestPresentation_SelectionMustAnswerEveryRequiredQuery(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, walletflowtest.MdocConfigurationID, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{mdocQuery(t, "mdl", "family_name"), f.env.SDJWTQuery(t, "pid", "family_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, c := range held {
		ids[c.Format] = c.ID
	}
	if _, err := p.Preview(ctx, walletflow.Selection{"pid": {ids["dc+sd-jwt"]}}); !errors.Is(err, walletflow.ErrInvalidSelection) || !strings.Contains(err.Error(), `"mdl" is required`) {
		t.Errorf("leaving mdl out = %v, want ErrInvalidSelection naming it", err)
	}
	if _, err := p.Preview(ctx, walletflow.Selection{"pid": {ids["mso_mdoc"]}, "mdl": {ids["mso_mdoc"]}}); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Errorf("an mdoc for the SD-JWT VC query = %v, want ErrInvalidSelection", err)
	}
	if _, err := p.Preview(ctx, walletflow.Selection{"pid": {ids["dc+sd-jwt"]}, "mdl": {ids["mso_mdoc"]}}); err != nil {
		t.Errorf("both answered: %v", err)
	}
}
