package issuerapp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletprovider"
)

// TestPreAuthorized_IssuesWithPINAndWalletAttestation: an offer "at the
// counter" is redeemed with its PIN and the wallet's Wallet Attestation
// — authenticated by fapigo/server's own check — with no browser
// approval, and issues both formats.
func TestPreAuthorized_IssuesWithPINAndWalletAttestation(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreatePreAuthorizedTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if !offer.PreAuthorized || !strings.Contains(offer.URI, "pre-authorized_code") {
		t.Fatalf("offer = %+v, want a pre-authorized code offer", offer)
	}
	if md := get(t, env, "/.well-known/oauth-authorization-server"); !strings.Contains(md, "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
		t.Error("the Authorization Server's metadata doesn't list the pre-authorized code grant")
	}
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil || len(received) != 2 {
		t.Fatalf("Receive = %d credentials, %v; want both", len(received), err)
	}
	if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err == nil {
		t.Error("a pre-authorized code was redeemed twice")
	}
}

// TestPreAuthorized_Refuses: a wrong PIN, or a wallet another Wallet
// Provider attests, gets no token — and neither spends the code.
func TestPreAuthorized_Refuses(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreatePreAuthorizedTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	wrong := "000000"
	if offer.ConfirmationCode == wrong {
		wrong = "111111"
	}
	if _, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: wrong}); err == nil || !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("wrong PIN: %v, want invalid_grant", err)
	}

	other, err := walletprovider.New(demotest.ProviderIssuer)
	if err != nil {
		t.Fatal(err)
	}
	otherSrv := httptest.NewTLSServer(other.Handler(demotest.WalletClientID))
	defer otherSrv.Close()
	cfg := env.WalletConfig()
	cfg.Provider = walletprovider.Client{URL: otherSrv.URL, HTTP: otherSrv.Client()}
	if _, err := walletapp.Receive(ctx, cfg, offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Errorf("untrusted Wallet Provider: %v, want invalid_client", err)
	}

	if received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil || len(received) != 2 {
		t.Fatalf("the trusted wallet afterwards: %d credentials, %v; want the code still redeemable", len(received), err)
	}
}

// TestAuthorize_RefusesRepeatedParameters: the authorization endpoint
// refuses a repeated client_id or request_uri (RFC 6749 §3.1) with a
// local error, rather than taking the first.
func TestAuthorize_RefusesRepeatedParameters(t *testing.T) {
	env := demotest.New(t, nil)
	for _, query := range []string{"client_id=a&client_id=b&request_uri=x", "client_id=a&request_uri=x&request_uri=y"} {
		resp, err := env.HTTP.Get(env.IssuerURL + "/authorize?" + query)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%s: status %d, want 400", query, resp.StatusCode)
		}
	}
}

// otherBrowserApprover opens the approval page in one browser and posts
// the decision from another — or cross-origin from the same one — as an
// attacker who saw the page might, and reports the decision's status.
type otherBrowserApprover struct {
	http   *http.Client
	code   string
	origin string // set: post from the same browser with this Origin
	status *int
}

func (o otherBrowserApprover) Approve(ctx context.Context, authorizationURL string, _ client.SessionHandle) (walletapp.Callback, error) {
	jar, _ := cookiejar.New(nil)
	opener := *o.http
	opener.Jar = jar
	opener.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := opener.Get(authorizationURL)
	if err != nil {
		return walletapp.Callback{}, err
	}
	page, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	// The attacker saw the page, tag included.
	tag, err := walletapp.ApprovalTag(page)
	if err != nil {
		return walletapp.Callback{}, err
	}

	poster := *o.http
	poster.CheckRedirect = opener.CheckRedirect
	if o.origin != "" {
		poster.Jar = jar
	}
	u, _ := url.Parse(authorizationURL)
	decision := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/authorize/decision"}).String()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, decision, strings.NewReader(url.Values{"interaction": {tag}, "decision": {"approve"}, "code": {o.code}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if o.origin != "" {
		req.Header.Set("Origin", o.origin)
	}
	resp, err = poster.Do(req)
	if err != nil {
		return walletapp.Callback{}, err
	}
	_ = resp.Body.Close()
	*o.status = resp.StatusCode
	return walletapp.Callback{}, errors.New("not approved")
}

// TestApproval_BoundToTheBrowser: the approval step's state lives in the
// sealed cookie of the browser that opened the page, so a decision
// posted from another browser, or cross-origin, is refused — and the
// offer can still be redeemed.
func TestApproval_BoundToTheBrowser(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		origin string
		want   int
	}{
		"another browser": {"", http.StatusBadRequest},
		"cross-origin":    {"https://attacker.example", http.StatusForbidden},
	} {
		var status int
		_, _ = walletapp.Receive(ctx, env.WalletConfig(), offer.URI, otherBrowserApprover{http: env.HTTP, code: offer.ConfirmationCode, origin: tc.origin, status: &status})
		if status != tc.want {
			t.Errorf("%s: decision status %d, want %d", name, status, tc.want)
		}
	}
	if received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}); err != nil || len(received) != 2 {
		t.Fatalf("Receive in the approving browser: %d credentials, %v; want both", len(received), err)
	}
}

// TestApproval_ReplacedInteraction: a second authorization in the same
// browser replaces the first one's cookie, and the first page's form —
// whose tag names the replaced interaction — is refused rather than
// completing the second.
func TestApproval_ReplacedInteraction(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	first, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	second, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	b := *env.HTTP
	b.Jar = jar
	b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// An approver that opens its page in the shared browser b and
	// returns the page's tag, without deciding.
	open := func(offerURI string) (string, string) {
		var tag, authURL string
		_, _ = walletapp.Receive(ctx, env.WalletConfig(), offerURI, approverFunc(func(authorizationURL string) error {
			resp, err := b.Get(authorizationURL)
			if err != nil {
				return err
			}
			page, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			authURL = authorizationURL
			if tag, err = walletapp.ApprovalTag(page); err != nil {
				return err
			}
			return errors.New("stop")
		}))
		return tag, authURL
	}
	firstTag, authURL := open(first.URI)
	if firstTag == "" {
		t.Fatal("no tag on the first approval page")
	}
	if secondTag, _ := open(second.URI); secondTag == "" || secondTag == firstTag {
		t.Fatalf("second tag %q, want a fresh one", secondTag)
	}
	u, _ := url.Parse(authURL)
	decision := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/authorize/decision"}).String()
	resp, err := b.PostForm(decision, url.Values{"interaction": {firstTag}, "decision": {"approve"}, "code": {first.ConfirmationCode}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("the replaced page's form: status %d, want 400", resp.StatusCode)
	}
}

// approverFunc opens an authorization URL and stops the flow.
type approverFunc func(authorizationURL string) error

func (f approverFunc) Approve(_ context.Context, authorizationURL string, _ client.SessionHandle) (walletapp.Callback, error) {
	return walletapp.Callback{}, f(authorizationURL)
}
