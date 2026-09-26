package walletapp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HeadlessApprover approves without a browser, by reading the demo
// issuer's X-Interaction-Handle header and posting "approve" to its
// /authorize/decision endpoint — the demo issuer's own convention, not
// a standard. For tests and scripted demos.
type HeadlessApprover struct {
	HTTP *http.Client // nil means a 10 s timeout client
}

// Approve implements Approver.
func (h HeadlessApprover) Approve(ctx context.Context, authorizationURL string) (string, error) {
	hc := &http.Client{Timeout: httpTimeout}
	if h.HTTP != nil {
		copied := *h.HTTP
		hc = &copied
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizationURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	handle := resp.Header.Get("X-Interaction-Handle")
	if resp.StatusCode != http.StatusOK || handle == "" {
		return "", fmt.Errorf("authorization page: status %d, no interaction handle", resp.StatusCode)
	}

	u, err := url.Parse(authorizationURL)
	if err != nil {
		return "", err
	}
	decision := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/authorize/decision"}).String()
	form := url.Values{"handle": {handle}, "decision": {"approve"}}
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, decision, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = hc.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("approval: status %d, no redirect: %w", resp.StatusCode, err)
	}
	return loc.RawQuery, nil
}

// BrowserApprover has the holder approve in a browser: it shows the
// authorization URL (via Show) and waits for the redirect on the
// wallet's loopback redirect URI.
type BrowserApprover struct {
	RedirectURI string // an http://127.0.0.1:<port>/<path> loopback URI
	Show        func(authorizationURL string)
	Timeout     time.Duration // zero means 5 minutes
}

// Approve implements Approver.
func (b BrowserApprover) Approve(ctx context.Context, authorizationURL string) (string, error) {
	redirect, err := url.Parse(b.RedirectURI)
	if err != nil || redirect.Scheme != "http" {
		return "", fmt.Errorf("browser approval needs an http loopback redirect URI, got %q", b.RedirectURI)
	}
	ln, err := net.Listen("tcp", redirect.Host)
	if err != nil {
		return "", fmt.Errorf("listen on %s: %w", redirect.Host, err)
	}

	got := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+redirect.EscapedPath(), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Done — you can close this window and return to the wallet.\n")
		select {
		case got <- r.URL.RawQuery:
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
	case q := <-got:
		return q, nil
	case <-time.After(timeout):
		return "", errors.New("timed out waiting for approval in the browser")
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
