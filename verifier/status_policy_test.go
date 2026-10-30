package verifier_test

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// productionStatus is a StatusPolicy AssuranceProduction accepts: a
// hardened Fetcher (the zero one) and an explicit revocation choice.
func productionStatus() *verifier.StatusPolicy {
	return &verifier.StatusPolicy{Checker: statuslist.Checker{
		Roots:   x509.NewCertPool(),
		Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
	}}
}

// The status decision is Status or NoStatusCheck, never both; under
// AssuranceProduction one of them is required, and Status's Fetcher
// must be hardened and its list signers' revocation decided.
func TestCheckStatusDecision(t *testing.T) {
	loopback := productionStatus()
	loopback.Checker.Fetcher.AllowLoopback = true
	noRevocation := productionStatus()
	noRevocation.Checker.Options.Revocation = nil
	noRoots := productionStatus()
	noRoots.Checker.Roots = nil
	for name, tc := range map[string]struct {
		assurance     verifier.AssuranceLevel
		status        *verifier.StatusPolicy
		noStatusCheck bool
		refuse        string
	}{
		"production, Status":                 {verifier.AssuranceProduction, productionStatus(), false, ""},
		"production, NoStatusCheck":          {verifier.AssuranceProduction, nil, true, ""},
		"production, neither":                {verifier.AssuranceProduction, nil, false, "NoStatusCheck"},
		"production, both":                   {verifier.AssuranceProduction, productionStatus(), true, "not both"},
		"production, loopback fetcher":       {verifier.AssuranceProduction, loopback, false, "HardenedForProduction"},
		"production, no revocation decision": {verifier.AssuranceProduction, noRevocation, false, "Revocation is required"},
		"production, no roots":               {verifier.AssuranceProduction, noRoots, false, "Roots"},
		"development, neither":               {verifier.AssuranceDevelopment, nil, false, ""},
		"development, loopback fetcher":      {verifier.AssuranceDevelopment, loopback, false, ""},
		"development, both":                  {verifier.AssuranceDevelopment, productionStatus(), true, "not both"},
		"development, no roots":              {verifier.AssuranceDevelopment, noRoots, false, "Roots"},
	} {
		err := verifier.CheckStatusDecision(tc.assurance, tc.status, tc.noStatusCheck)
		switch {
		case tc.refuse == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refuse != "" && (err == nil || !strings.Contains(err.Error(), tc.refuse)):
			t.Errorf("%s: %v, want refused naming %s", name, err, tc.refuse)
		}
	}
}

// Transactions runs Status before Accept, and its refusal is recorded
// as LastError, with the request left open: here, a credential with no
// status reference under RequireReference.
func TestTransactions_StatusRunsBeforeAccept(t *testing.T) {
	ctx := context.Background()
	accepted := 0
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) {
		c.Status = &verifier.StatusPolicy{Checker: statuslist.Checker{Roots: x509.NewCertPool()}, RequireReference: true}
		c.Accept = func(context.Context, string, verifier.VerifyResponseResult) error {
			accepted++
			return nil
		}
	})
	begun := f.begin("browser-binding-A", false)
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err == nil || !strings.Contains(err.Error(), "status reference") {
		t.Fatalf("HandleResponse = %v, want refused by Status", err)
	}
	if accepted != 0 {
		t.Errorf("Accept ran %d times after Status refused the answer", accepted)
	}
	view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A")
	if err != nil || view.Status != verifier.TransactionPending || !strings.Contains(view.LastError, "status reference") {
		t.Errorf("after the refusal: %+v, %v; want still pending, with Status's reason", view, err)
	}
}

// A direct VerifyResponse runs Status, then Accept, on what verified.
func TestVerifyResponse_StatusRunsBeforeAccept(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-binding-A", false)
	tx, err := f.store.Get(ctx, begun.ID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := f.v.ParseDirectPostJWTResponse(f.answer(begun, nil), tx.ResponseDecryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	req := f.verify
	req.Query, req.Response, req.ExpectedNonce, req.ResponseEncryptionKey = tx.Query, parsed, tx.Nonce, tx.ResponseDecryptionKey
	req.Status = &verifier.StatusPolicy{Checker: statuslist.Checker{Roots: x509.NewCertPool()}}
	req.Accept = verifier.Chain(
		func(context.Context, string, verifier.VerifyResponseResult) error {
			order = append(order, "first")
			return nil
		},
		nil,
		func(context.Context, string, verifier.VerifyResponseResult) error {
			order = append(order, "second")
			return nil
		},
	)
	if _, err := f.v.VerifyResponse(ctx, req); err != nil || strings.Join(order, ",") != "first,second" {
		t.Fatalf("VerifyResponse = %v, Accept ran %v; want accepted, both in order", err, order)
	}
	order = nil
	req.Status.RequireReference = true
	if _, err := f.v.VerifyResponse(ctx, req); err == nil || len(order) != 0 {
		t.Errorf("VerifyResponse = %v, Accept ran %v; want refused by Status before Accept", err, order)
	}
}

// Chain stops at the first refusal.
func TestChain(t *testing.T) {
	refusal := errors.New("refused")
	ran := 0
	count := func(context.Context, string, verifier.VerifyResponseResult) error { ran++; return nil }
	refuse := func(context.Context, string, verifier.VerifyResponseResult) error { return refusal }
	if err := verifier.Chain(count, refuse, count)(context.Background(), "id", verifier.VerifyResponseResult{}); !errors.Is(err, refusal) || ran != 1 {
		t.Errorf("Chain = %v after %d, want the refusal after 1", err, ran)
	}
	if err := verifier.Chain()(context.Background(), "id", verifier.VerifyResponseResult{}); err != nil {
		t.Errorf("an empty Chain: %v", err)
	}
}
