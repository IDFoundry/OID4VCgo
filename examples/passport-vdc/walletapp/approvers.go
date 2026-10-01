package walletapp

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/client"
)

// HeadlessApprover approves without a browser, as a holder would: it
// reads the interaction handle from the demo issuer's approval form
// (ApprovalHandle) and posts "approve" with the offer's confirmation
// code to its /authorize/decision endpoint. For tests and scripted
// demos.
type HeadlessApprover struct {
	HTTP *http.Client // nil means a 10 s timeout client
	// Code is the confirmation code shown with the offer.
	Code string
}

// Approve implements Approver. There's no user agent but this process, so
// session comes straight back with the callback.
func (h HeadlessApprover) Approve(ctx context.Context, authorizationURL string, session client.SessionHandle) (Callback, error) {
	hc := &http.Client{Timeout: httpTimeout}
	if h.HTTP != nil {
		copied := *h.HTTP
		hc = &copied
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizationURL, nil)
	if err != nil {
		return Callback{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Callback{}, err
	}
	page, err := io.ReadAll(io.LimitReader(resp.Body, maxApprovalPageBytes))
	_ = resp.Body.Close()
	if err != nil {
		return Callback{}, fmt.Errorf("authorization page: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Callback{}, fmt.Errorf("authorization page: status %d", resp.StatusCode)
	}
	handle, err := ApprovalHandle(page)
	if err != nil {
		return Callback{}, err
	}

	u, err := url.Parse(authorizationURL)
	if err != nil {
		return Callback{}, err
	}
	decision := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/authorize/decision"}).String()
	form := url.Values{"handle": {handle}, "decision": {"approve"}, "code": {h.Code}}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, decision, strings.NewReader(form.Encode()))
	if err != nil {
		return Callback{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = hc.Do(req)
	if err != nil {
		return Callback{}, err
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		return Callback{}, fmt.Errorf("approval: status %d, no redirect: %w", resp.StatusCode, err)
	}
	return Callback{Query: loc.RawQuery, Session: session}, nil
}

// maxApprovalPageBytes bounds the approval page HeadlessApprover reads.
const maxApprovalPageBytes = 1 << 20

// approvalHandleField matches the demo issuer's approval form's hidden
// interaction handle field.
var approvalHandleField = regexp.MustCompile(`<input type="hidden" name="handle" value="([^"]*)">`)

// ApprovalHandle returns the interaction handle in the demo issuer's
// approval page: the hidden "handle" field its form posts to
// /authorize/decision.
func ApprovalHandle(page []byte) (string, error) {
	m := approvalHandleField.FindSubmatch(page)
	if m == nil || len(m[1]) == 0 {
		return "", errors.New("authorization page: no interaction handle in its approval form")
	}
	return html.UnescapeString(string(m[1])), nil
}

// BrowserApprover has the holder approve in a browser: it shows the
// authorization URL (via Show) and waits for the redirect on the
// wallet's loopback redirect URI.
//
// The flow's session handle comes straight back with the callback, as
// with HeadlessApprover: this process is the user agent the flow is bound
// to. Its session store holds only the flow it began, so a callback from
// anyone else's flow — a URL delivered to the holder's browser — finds no
// session and is refused. (A web wallet, whose one session store serves
// every browser, binds the callback to the browser with a cookie instead:
// see the webwallet package.)
type BrowserApprover struct {
	RedirectURI string // an http://127.0.0.1:<port>/<path> loopback URI
	Show        func(authorizationURL string)
	Timeout     time.Duration // zero means 5 minutes
}

// Approve implements Approver.
func (b BrowserApprover) Approve(ctx context.Context, authorizationURL string, session client.SessionHandle) (Callback, error) {
	redirect, err := url.Parse(b.RedirectURI)
	if err != nil || redirect.Scheme != "http" {
		return Callback{}, fmt.Errorf("browser approval needs an http loopback redirect URI, got %q", b.RedirectURI)
	}
	ln, err := net.Listen("tcp", redirect.Host)
	if err != nil {
		return Callback{}, fmt.Errorf("listen on %s: %w", redirect.Host, err)
	}

	got := make(chan Callback, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+redirect.EscapedPath(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Done — you can close this window and return to the wallet.\n")
		select {
		case got <- Callback{Query: r.URL.RawQuery, Session: session}:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	if b.Show != nil {
		b.Show(authorizationURL)
	}
	timeout := b.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	select {
	case cb := <-got:
		return cb, nil
	case <-time.After(timeout):
		return Callback{}, errors.New("timed out waiting for approval in the browser")
	case <-ctx.Done():
		return Callback{}, ctx.Err()
	}
}
