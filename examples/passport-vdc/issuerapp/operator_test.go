package issuerapp_test

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// reviewCounts GETs the review status, checking it's never cached and
// carries only the counts.
func reviewCounts(t *testing.T, env *demotest.Env) map[string]any {
	t.Helper()
	resp, err := env.HTTP.Get(env.IssuerURL + "/demo/review/status")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("review status headers: %v", resp.Header)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("review status %s: %v", body, err)
	}
	if len(out) != 2 || out["pending"] == nil || out["total"] == nil {
		t.Errorf("review status = %s, want only pending and total", body)
	}
	return out
}

// TestReviewPage_Cards: the review page shows each issuance as a card,
// its state as a badge and Approve and Deny side by side; it refreshes
// from a status endpoint that counts, and nothing more; and the header
// counts what awaits review.
func TestReviewPage_Cards(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	if c := reviewCounts(t, env); c["pending"] != float64(0) || c["total"] != float64(0) {
		t.Errorf("no reviews: %v", c)
	}
	if page := get(t, env, "/demo/review"); !strings.Contains(page, "Nothing is awaiting review") || !strings.Contains(page, `aria-live="polite"`) {
		t.Error("the empty review page lacks its message or live region")
	}
	e := demotest.SyntheticEvidence()
	offer, err := env.Issuer.CreateTransactionForReview(ctx, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := walletapp.ReceiveDeferrable(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil {
		t.Fatal(err)
	}
	if err := env.Issuer.Review(env.Issuer.Reviews()[0].Ref, true); err != nil {
		t.Fatal(err)
	}
	if c := reviewCounts(t, env); c["pending"] != float64(1) || c["total"] != float64(2) {
		t.Errorf("one decided of two: %v", c)
	}
	page := get(t, env, "/demo/review")
	for _, want := range []string{
		`<ul class="entries">`, `<li class="card entry">`, `<span class="badge warn">Awaiting review</span>`, `<span class="badge ok">✓ Approved</span>`,
		`<button class="btn" name="decision" value="approve">Approve</button> <button class="btn secondary danger" name="decision" value="deny">Deny</button>`,
		`"/demo/review/status"`, `<noscript><meta http-equiv="refresh"`, `Review <span class="count">1</span>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the review page lacks %q", want)
		}
	}
}

// TestStatusPage_ConfirmsRevocation: a credential is revoked in two
// steps on the page — Revoke, then Confirm revoke — without a script,
// and the wallets' notifications read as a timeline.
func TestStatusPage_ConfirmsRevocation(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil {
		t.Fatal(err)
	}
	resp, err := env.HTTP.Get(env.IssuerURL + "/demo/status")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	page := string(body)
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("status page Cache-Control = %q", resp.Header.Get("Cache-Control"))
	}
	// Each revoke form sits inside a closed <details>, behind its
	// summary, with the confirming button.
	forms := regexp.MustCompile(`<details class="confirm"><summary class="btn secondary danger"><span class="when-closed">Revoke…</span><span class="when-open">Cancel</span></summary>\n<form method="post" action="/demo/status/revoke"><input type="hidden" name="handle" value="[^"]+">\n<p class="note">[^<]+</p>\n<button class="btn danger">Confirm revoke</button></form>\n</details>`).FindAllString(page, -1)
	issued := len(env.Issuer.IssuedStatuses())
	if issued == 0 || len(forms) != issued || strings.Count(page, `action="/demo/status/revoke"`) != issued {
		t.Errorf("revoke forms behind a confirmation = %d, want one for each of %d credentials", len(forms), issued)
	}
	for _, want := range []string{`<span class="badge ok">✓ Valid</span>`, `<ol class="timeline">`, "credential_accepted", `<span class="badge ok">✓ Kept</span>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the status page lacks %q", want)
		}
	}
}

// TestKeptPage_ConfirmsForget: the kept page lists each kept passport
// as a card, and asks before forgetting one.
func TestKeptPage_ConfirmsForget(t *testing.T) {
	env := demotest.New(t, nil)
	if page := get(t, env, "/demo/kept"); !strings.Contains(page, "No passport is kept for refresh.") || !strings.Contains(page, `aria-current="page"`) {
		t.Error("the empty kept page lacks its message or current link")
	}
	offer, err := env.Issuer.CreateOffer(context.Background(), demotest.SyntheticEvidence(), issuerapp.OfferOptions{KeepForRefresh: true, PreAuthorized: true})
	if err != nil {
		t.Fatal(err)
	}
	receive(t, env, refreshingWallet(t, env), offer)
	page := get(t, env, "/demo/kept")
	if !regexp.MustCompile(`<details class="confirm"><summary[^>]*><span class="when-closed">Forget now…</span>.*</summary>\n<form method="post" action="/demo/kept/forget"><input type="hidden" name="ref" value="[^"]+">`).MatchString(page) ||
		!strings.Contains(page, `<button class="btn danger">Confirm forget</button>`) {
		t.Error("the kept page doesn't ask before forgetting")
	}
}
