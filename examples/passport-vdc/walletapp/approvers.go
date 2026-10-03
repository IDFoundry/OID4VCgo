package walletapp

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// HeadlessApprover approves without a browser, as a holder would: it
// opens the demo issuer's approval page, keeping the interaction cookie
// it sets, and submits its form — the interaction's tag
// (ApprovalTag), "approve" and the offer's confirmation code — to its
// /authorize/decision endpoint. For tests and scripted demos.
type HeadlessApprover struct {
	HTTP *http.Client // nil means a 10 s timeout client
	// Code is the confirmation code shown with the offer.
	Code string
}

// Approve implements Approver.
func (h HeadlessApprover) Approve(ctx context.Context, authorizationURL string) (Callback, error) {
	loc, err := h.Redirect(ctx, authorizationURL)
	if err != nil {
		return Callback{}, err
	}
	return Callback{Query: loc.RawQuery}, nil
}

// Redirect approves as Approve does, and returns where the issuer
// redirects the browser: the wallet's redirect URI, with the response.
func (h HeadlessApprover) Redirect(ctx context.Context, authorizationURL string) (*url.URL, error) {
	hc := &http.Client{Timeout: httpTimeout}
	if h.HTTP != nil {
		copied := *h.HTTP
		hc = &copied
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// The issuer keeps the approval's state in a cookie on the browser
	// that opened the page; this process is that browser.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	hc.Jar = jar

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizationURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	page, err := io.ReadAll(io.LimitReader(resp.Body, maxApprovalPageBytes))
	_ = resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("authorization page: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorization page: status %d", resp.StatusCode)
	}
	tag, err := ApprovalTag(page)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(authorizationURL)
	if err != nil {
		return nil, err
	}
	decision := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/authorize/decision"}).String()
	form := url.Values{approvalTagField: {tag}, "decision": {"approve"}, "code": {h.Code}}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, decision, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = hc.Do(req)
	if err != nil {
		return nil, err
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		return nil, fmt.Errorf("approval: status %d, no redirect: %w", resp.StatusCode, err)
	}
	return loc, nil
}

// maxApprovalPageBytes bounds the approval page HeadlessApprover reads.
const maxApprovalPageBytes = 1 << 20

// approvalTagField is the demo issuer's approval form field carrying the
// interaction's tag (fapigo's interactioncookie.FormField).
const approvalTagField = "interaction"

// approvalTagInput matches the approval form's hidden tag field.
var approvalTagInput = regexp.MustCompile(`<input type="hidden" name="` + approvalTagField + `" value="([^"]*)">`)

// ApprovalTag returns the interaction tag in the demo issuer's approval
// page: the hidden field its form posts back with the interaction
// cookie, so the issuer knows which interaction the form was for.
func ApprovalTag(page []byte) (string, error) {
	m := approvalTagInput.FindSubmatch(page)
	if m == nil || len(m[1]) == 0 {
		return "", errors.New("authorization page: no interaction tag in its approval form")
	}
	return html.UnescapeString(string(m[1])), nil
}

// BrowserApprover has the holder approve in a browser: it shows the
// authorization URL (via Show) and waits for the redirect on the
// wallet's loopback redirect URI.
//
// The callback is completed only for the flow this process began: a
// callback from anyone else's flow — a URL delivered to the holder's
// browser — doesn't match it and is refused. (A web wallet, serving many
// browsers, binds the callback to the browser with a cookie too: see the
// webwallet package.)
type BrowserApprover struct {
	// RedirectURI is an http://127.0.0.1/<path> loopback URI: without a
	// port, each authorization listens on one the operating system picks.
	RedirectURI string
	Show        func(authorizationURL string)
	Timeout     time.Duration // zero means 5 minutes
	// PromptPIN asks the holder for a pre-authorized offer's PIN; nil
	// means such an offer can't be received.
	PromptPIN func(txCode oid4vci.TxCode) (string, error)
}

// PIN implements PINApprover with PromptPIN.
func (b BrowserApprover) PIN(_ context.Context, txCode oid4vci.TxCode) (string, error) {
	if b.PromptPIN == nil {
		return "", errors.New("walletapp: the offer needs a PIN")
	}
	return b.PromptPIN(txCode)
}

// Approve implements Approver.
func (b BrowserApprover) Approve(ctx context.Context, authorizationURL string) (Callback, error) {
	l, err := b.Listen(ctx)
	if err != nil {
		return Callback{}, err
	}
	defer func() { _ = l.Close() }()
	return l.Approve(ctx, authorizationURL)
}

// Listen implements LoopbackApprover. A RedirectURI without a port
// (http://127.0.0.1/callback) listens on a port the operating system
// picks, and the wallet sends that port; one with a port listens on it.
func (b BrowserApprover) Listen(_ context.Context) (LoopbackListener, error) {
	redirect, err := url.Parse(b.RedirectURI)
	if err != nil || redirect.Scheme != "http" {
		return nil, fmt.Errorf("browser approval needs an http loopback redirect URI, got %q", b.RedirectURI)
	}
	perFlow := redirect.Port() == ""
	addr := redirect.Host
	if perFlow {
		addr = net.JoinHostPort(redirect.Hostname(), "0")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	l := &browserListener{approver: b, got: make(chan Callback, 1)}
	if perFlow {
		l.port = uint16(ln.Addr().(*net.TCPAddr).Port) //nolint:gosec // a TCP port fits
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+redirect.EscapedPath(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Done — you can close this window and return to the wallet.\n")
		select {
		case l.got <- Callback{Query: r.URL.RawQuery}:
		default:
		}
	})
	l.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = l.srv.Serve(ln) }()
	return l, nil
}

// browserListener is a BrowserApprover listening for one authorization's
// redirect.
type browserListener struct {
	approver BrowserApprover
	srv      *http.Server
	got      chan Callback
	port     uint16
}

func (l *browserListener) RedirectPort() uint16 { return l.port }

func (l *browserListener) Approve(ctx context.Context, authorizationURL string) (Callback, error) {
	if l.approver.Show != nil {
		l.approver.Show(authorizationURL)
	}
	timeout := l.approver.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	select {
	case cb := <-l.got:
		return cb, nil
	case <-time.After(timeout):
		return Callback{}, errors.New("timed out waiting for approval in the browser")
	case <-ctx.Done():
		return Callback{}, ctx.Err()
	}
}

func (l *browserListener) Close() error { return l.srv.Close() }
