package verifier_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// Under AssuranceProduction, a Transactions without RequestURIBase,
// which serves the Digital Credentials API alone, needs its own Scope:
// every such Transactions of one Verifier derives the same one, so a
// lax policy's could complete a strict one's requests under its own
// Verify and Accept.
func TestNewTransactions_ProductionDCAPIOnlyNeedsScope(t *testing.T) {
	f := newTxFixture(t, nil)
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	prod, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	verify := f.verify
	verify.AnyIssuerForAnyType = true
	txCfg := verifier.TransactionsConfig{Origins: []string{"https://verifier.example.com"}, Verify: verify, NoStatusCheck: true}
	if _, err := verifier.NewTransactions(prod, assuredTransactionStore{f.store}, txCfg); err == nil || !strings.Contains(err.Error(), "set scope") {
		t.Errorf("a production DC-API-only Transactions without a scope: %v, want refused", err)
	}
	txCfg.Scope = "login"
	if _, err := verifier.NewTransactions(prod, assuredTransactionStore{f.store}, txCfg); err != nil {
		t.Errorf("with a scope: %v", err)
	}
}
