package verifier_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// BeginDCAPI takes only an origin of TransactionsConfig.Origins, so one
// taken from the request can't bind a presentation to another page;
// under AssuranceProduction they're required.
func TestTransactions_DCAPIOrigins(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, func(cfg *verifier.TransactionsConfig) {
		cfg.Origins = []string{"HTTPS://Verifier.Example.com:443/", "http://localhost:8443"}
	})
	for _, origin := range []string{dcapiOrigin, "http://localhost:8443"} {
		if _, err := f.txs.BeginDCAPI(ctx, f.query, testBinding, origin); err != nil {
			t.Errorf("%q, one of Origins (normalized): %v", origin, err)
		}
	}
	for _, origin := range []string{"https://evil.example", "https://verifier.example.com:8443", "http://localhost:9000"} {
		if _, err := f.txs.BeginDCAPI(ctx, f.query, testBinding, origin); err == nil || !strings.Contains(err.Error(), "Origins") {
			t.Errorf("%q, not one of Origins: %v", origin, err)
		}
	}

	v := newTestVerifier(t)
	for name, origin := range map[string]string{
		"a path":         "https://verifier.example.com/app",
		"a query":        "https://verifier.example.com?x=1",
		"a fragment":     "https://verifier.example.com#x",
		"userinfo":       "https://u@verifier.example.com",
		"no scheme":      "verifier.example.com",
		"a non-loopback": "http://verifier.example.com",
	} {
		if _, err := verifier.NewTransactions(v, f.store, verifier.TransactionsConfig{Origins: []string{origin}}); err == nil {
			t.Errorf("Origins with %s (%q): accepted", name, origin)
		}
	}

	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	prod, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	verify := f.verify
	verify.AnyIssuerForAnyType = true
	prodCfg := verifier.TransactionsConfig{Verify: verify, NoStatusCheck: true, Scope: "dcapi"}
	// For the Digital Credentials API alone, the missing Origins show
	// in NewTransactions; with RequestURIBase, in BeginDCAPI.
	if _, err := verifier.NewTransactions(prod, assuredTransactionStore{f.store}, prodCfg); err == nil || !strings.Contains(err.Error(), "origins") {
		t.Errorf("NewTransactions under AssuranceProduction with neither RequestURIBase nor Origins: %v", err)
	}
	redirectCfg := prodCfg
	redirectCfg.RequestURIBase = txBase
	withoutOrigins, err := verifier.NewTransactions(prod, assuredTransactionStore{f.store}, redirectCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withoutOrigins.BeginDCAPI(ctx, f.query, testBinding, dcapiOrigin); err == nil || !strings.Contains(err.Error(), "Origins") {
		t.Errorf("BeginDCAPI under AssuranceProduction without Origins: %v", err)
	}
	prodCfg.Origins = []string{"http://localhost:8443"}
	if _, err := verifier.NewTransactions(prod, assuredTransactionStore{f.store}, prodCfg); err == nil {
		t.Error("a loopback http origin under AssuranceProduction: accepted")
	}
	prodCfg.Origins = []string{dcapiOrigin}
	withOrigins, err := verifier.NewTransactions(prod, assuredTransactionStore{f.store}, prodCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withOrigins.BeginDCAPI(ctx, f.query, testBinding, dcapiOrigin); err != nil {
		t.Errorf("BeginDCAPI under AssuranceProduction with its origin: %v", err)
	}
	if _, err := withOrigins.BeginDCAPI(ctx, f.query, testBinding, "https://evil.example"); err == nil {
		t.Error("BeginDCAPI under AssuranceProduction with another origin: accepted")
	}
}
