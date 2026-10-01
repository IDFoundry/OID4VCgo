package issuerapp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// TestDeferred_ReviewDecides: a passport uploaded for review is
// deferred. The wallet polls while the operator hasn't decided; once
// they have, its next poll gets the approved credential (validated, and
// reported to the issuer as accepted) or is told the denied one is
// refused.
func TestDeferred_ReviewDecides(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransactionForReview(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	received, pending, err := walletapp.ReceiveDeferrable(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 0 || len(pending) != 2 {
		t.Fatalf("ReceiveDeferrable = %d received, %d pending, %v; want both deferred", len(received), len(pending), err)
	}
	if pending[0].Interval <= 0 {
		t.Errorf("Interval = %v, want the issuer's polling interval", pending[0].Interval)
	}
	for _, p := range pending {
		if r, err := p.Poll(ctx); r != nil || err != nil {
			t.Fatalf("poll before a decision = %v, %v; want still pending", r, err)
		}
	}

	reviews := env.Issuer.Reviews()
	if len(reviews) != 2 {
		t.Fatalf("Reviews = %+v, want two awaiting review", reviews)
	}
	byFormat := map[string]string{}
	for _, rv := range reviews {
		byFormat[rv.Format] = rv.Ref
	}
	approved, denied := pending[0], pending[1]
	if err := env.Issuer.Review(byFormat[approved.Format], true); err != nil {
		t.Fatal(err)
	}
	if err := env.Issuer.Review(byFormat[denied.Format], false); err != nil {
		t.Fatal(err)
	}
	if err := env.Issuer.Review(byFormat[denied.Format], true); err == nil {
		t.Error("a review was decided twice")
	}

	r, err := approved.Poll(ctx)
	if err != nil || r == nil || r.Format != approved.Format || r.Credential == "" {
		t.Fatalf("poll after approval = %+v, %v; want the credential", r, err)
	}
	if _, err := denied.Poll(ctx); !errors.Is(err, walletapp.ErrDenied) {
		t.Fatalf("poll after denial = %v, want ErrDenied", err)
	}
	if len(env.Issuer.Reviews()) != 0 {
		t.Error("decided reviews are still held after the wallet's polls")
	}
	if n := env.Issuer.Notifications(); len(n) != 1 || n[0].Event != oid4vci.NotificationEventCredentialAccepted {
		t.Errorf("Notifications = %+v, want the approved credential accepted", n)
	}
	if statuses := env.Issuer.IssuedStatuses(); len(statuses) != 1 {
		t.Errorf("IssuedStatuses = %d, want a status entry for the approved credential only", len(statuses))
	}
}

// TestDeferred_ReceiveWaits: Receive waits for a deferred credential,
// telling OnPending, and returns it once approved.
func TestDeferred_ReceiveWaits(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransactionForReview(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	cfg := env.WalletConfig()
	told := 0
	cfg.OnPending = func(*walletapp.Pending) {
		told++
		for _, rv := range env.Issuer.Reviews() {
			_ = env.Issuer.Review(rv.Ref, true)
		}
	}
	received, err := walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 2 || told != 2 {
		t.Fatalf("Receive = %d credentials, %v (OnPending told %d times); want both, after waiting for each", len(received), err, told)
	}
}

// TestNotifications_ReportImmediateIssuance: the wallet reports each
// credential it kept, and the status page shows it.
func TestNotifications_ReportImmediateIssuance(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil {
		t.Fatal(err)
	}
	n := env.Issuer.Notifications()
	if len(n) != 2 || n[0].Event != oid4vci.NotificationEventCredentialAccepted || n[1].Event != oid4vci.NotificationEventCredentialAccepted {
		t.Fatalf("Notifications = %+v, want both credentials accepted", n)
	}
	if page := get(t, env, "/status"); !strings.Contains(page, "credential_accepted") {
		t.Error("the status page doesn't show the wallet's notifications")
	}
}

// TestReviewPage: the review page lists what's awaiting a decision
// without the holder's name or document number, and refuses a
// cross-origin decision.
func TestReviewPage(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	e := demotest.SyntheticEvidence()
	offer, err := env.Issuer.CreateTransactionForReview(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := walletapp.ReceiveDeferrable(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil {
		t.Fatal(err)
	}
	page := get(t, env, "/review")
	if !strings.Contains(page, e.Identity.IssuingCountry) || strings.Count(page, `name="ref"`) != 2 {
		t.Errorf("review page doesn't list both deferred issuances:\n%s", page)
	}
	if strings.Contains(page, e.Identity.FamilyName) || strings.Contains(page, e.Identity.DocumentNumber) {
		t.Error("the review page shows the holder's name or document number")
	}

	ref := env.Issuer.Reviews()[0].Ref
	req, err := http.NewRequest(http.MethodPost, env.IssuerURL+"/review/decision", strings.NewReader(url.Values{"ref": {ref}, "decision": {"approve"}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.example")
	resp, err := env.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || env.Issuer.Reviews()[0].Decision != "awaiting review" {
		t.Errorf("cross-origin decision: status %d, review %+v; want it refused", resp.StatusCode, env.Issuer.Reviews()[0])
	}
}

func get(t *testing.T, env *demotest.Env, path string) string {
	t.Helper()
	resp, err := env.HTTP.Get(env.IssuerURL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
