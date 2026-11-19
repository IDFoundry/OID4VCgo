package walletflow_test

import (
	"context"
	"errors"
	"slices"
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
	if view := v.Lookup(t, id); view.LastError != "an error response arrived: access_denied" {
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
	// A credential set takes one of its options (OpenID4VP 1.0 §6.4.2):
	// answering both alternatives would disclose more than it needs.
	if _, err := p.Preview(ctx, walletflow.Selection{"mdl": {mdl}, "pid": {sdjwt}}); !errors.Is(err, walletflow.ErrInvalidSelection) {
		t.Errorf("both options answered = %v, want ErrInvalidSelection", err)
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

// The preview names the claims the issuer issued in plaintext: they go
// to the Verifier with whatever it asked for, so the consent screen
// must show them too.
func TestPresentation_PreviewShowsAlwaysDisclosed(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{PlainClaims: map[string]any{"nationality": "SG"}})
	v := f.env.StartVerifier(t)
	w := f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	id, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	disclosed, err := p.Preview(ctx, sel)
	if err != nil || len(disclosed) != 1 {
		t.Fatalf("Preview = %+v, %v", disclosed, err)
	}
	if a := disclosed[0].AlwaysDisclosed; len(a) != 1 || len(a[0]) != 1 || a[0][0].Key() != "nationality" {
		t.Fatalf("AlwaysDisclosed = %v, want [nationality]", a)
	}
	if _, err := p.Respond(ctx, sel); err != nil {
		t.Fatal(err)
	}
	if view := v.Lookup(t, id); view.Result.Credentials[0].Claims["nationality"] != "SG" {
		t.Errorf("the Verifier received %v, without the plaintext claim the preview named", view.Result.Credentials[0].Claims)
	}
}

// A query that takes several credentials (multiple) permits them; the
// wallet's own choice is still the first, as Queries lists them, and the
// holder adds the others.
func TestPresentation_DefaultSelectionTakesOneForMultiple(t *testing.T) {
	f, v, w := presentationFixture(t)
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	q := f.env.SDJWTQuery(t, "pid", "given_name")
	q.Multiple = true
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{q}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	candidates := p.Queries()[0].Credentials
	if len(candidates) != 2 {
		t.Fatalf("query offers %d credentials, want both held", len(candidates))
	}
	sel, err := p.DefaultSelection(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := sel["pid"]; len(got) != 1 || got[0] != candidates[0].ID {
		t.Errorf("DefaultSelection[pid] = %v, want the first candidate, %s", got, candidates[0].ID)
	}
	both := walletflow.Selection{"pid": {candidates[0].ID, candidates[1].ID}}
	if _, err := p.Preview(ctx, both); err != nil {
		t.Errorf("the holder adding the other: %v", err)
	}
}

// A credential refreshed between Preview and Respond isn't presented:
// what would be sent isn't what the holder was shown.
func TestPresentation_RefreshedSinceShown(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	v := f.env.StartVerifier(t)
	w := f.newRefreshingWallet(t, v.Trust, walletflow.NewMemoryGrantStore())
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID)
	ctx := context.Background()
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	sel := walletflow.Selection{"pid": {held[0].ID}}
	if _, err := p.Preview(ctx, sel); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.RefreshCredential(ctx, held[0].ID); err != nil {
		t.Fatalf("RefreshCredential: %v", err)
	}
	if _, err := p.Respond(ctx, sel); !errors.Is(err, walletflow.ErrCredentialChanged) {
		t.Fatalf("Respond after a refresh = %v, want ErrCredentialChanged", err)
	}
	// A new presentation shows, and sends, the refreshed credential.
	_, link = v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}})
	if p, err = w.StartPresentation(ctx, link); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Respond(ctx, sel); err != nil {
		t.Errorf("Respond in a new presentation: %v", err)
	}
}

// The preview reports the claims the Verifier says it will keep (an
// mdoc query's intent_to_retain, OpenID4VP Appendix B.2.4), for the
// consent screen to show.
func TestPresentation_PreviewRetained(t *testing.T) {
	f, v, w := presentationFixture(t)
	held := receive(t, f, w, walletflowtest.MdocConfigurationID)
	ctx := context.Background()
	q := mdocQuery(t, "mdl", "family_name", "given_name")
	keep := true
	q.Claims[0].IntentToRetain = &keep
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{q}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	disclosed, err := p.Preview(ctx, walletflow.Selection{"mdl": {held[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	if len(disclosed) != 1 || len(disclosed[0].Retained) != 1 || !slices.Equal(disclosed[0].Retained[0], q.Claims[0].Path) {
		t.Errorf("Retained = %v, want only %v", disclosed[0].Retained, q.Claims[0].Path)
	}
}

// One credential selected for two queries is presented with one copy:
// two would give the Verifier two holder keys of one credential, burn
// a copy, and link the two to one holder.
func TestRespond_OneCopyPerCredential(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	v := f.env.StartVerifier(t)
	w := f.newWalletTrusting(t, f.env.IssuerRoots, v.Trust)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	ctx := context.Background()
	_, link := v.Begin(t, dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "a", "given_name"), f.env.SDJWTQuery(t, "b", "family_name")}})
	p, err := w.StartPresentation(ctx, link)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Respond(ctx, walletflow.Selection{"a": {held.ID}, "b": {held.ID}}); err != nil {
		t.Fatal(err)
	}
	stored, err := f.store.Get(ctx, held.ID)
	if err != nil {
		t.Fatal(err)
	}
	if left := stored.CopiesLeft(); left != 2 {
		t.Errorf("copies left = %d, want 2: one copy for both queries", left)
	}
}

// A signed request carrying transaction_data, which the wallet
// recognizes none of, is refused, the Verifier told, and the redirect_uri
// it answers the error response with handed back.
func TestPresentation_RefusedRequestGivesTheRedirect(t *testing.T) {
	f, v, w := presentationFixture(t)
	link, err := v.BeginRefused(dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", "given_name")}}, "https://verifier.walletflowtest.example/done")
	if err != nil {
		t.Fatal(err)
	}
	_, err = w.StartPresentation(context.Background(), link)
	var refused *walletflow.RequestRefusedError
	if !errors.As(err, &refused) || !errors.Is(err, walletflow.ErrRequestRefused) {
		t.Fatalf("StartPresentation = %v, want a RequestRefusedError", err)
	}
	if refused.Code != "invalid_transaction_data" || refused.RedirectURI != "https://verifier.walletflowtest.example/done" {
		t.Errorf("refused = %+v", refused)
	}
	if strings.Contains(err.Error(), "wasn't told") {
		t.Errorf("the Verifier wasn't told: %v", err)
	}
}
