package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// authorization is how the authorization code grant went: the
// authorization page's answer to the browser, and whether the redirect
// it led to came back to the wallet's redirect URI.
type authorization struct {
	// Status is the authorization endpoint's HTTP status, and
	// Redirected whether it redirected to the wallet's redirect URI.
	Status     int  `json:"status"`
	Redirected bool `json:"redirected"`
}

// maxPage bounds what authorize reads of a page that doesn't redirect.
const maxPage = 64 << 10

// authorize redeems s's offer by the authorization code grant: it sends
// the Pushed Authorization Request (BeginAuthorization), opens the
// authorization URL as the holder's browser would, over client's
// transport, following its redirects until one comes back to the
// wallet's redirect URI, and hands that to CompleteAuthorization. An
// issuer that authenticates the holder on its page (a login form)
// isn't followed: authorize fails, naming the page's status.
func authorize(ctx context.Context, s *walletflow.Issuance, client *http.Client, redirectURI string, res *result) error {
	res.Stage = "authorization"
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		return err
	}
	res.Authorization = &authorization{}
	browser := &http.Client{Transport: client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	next := authURL
	for hops := 0; hops < 5; hops++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		resp, err := browser.Do(req) // #nosec G107 -- the issuer's authorization endpoint, which the run trusts
		if err != nil {
			return err
		}
		page, _ := io.ReadAll(io.LimitReader(resp.Body, maxPage))
		_ = resp.Body.Close()
		res.Authorization.Status = resp.StatusCode
		location, err := resp.Location()
		if err != nil {
			return fmt.Errorf("the authorization endpoint answered %d without a redirect: %.200s", resp.StatusCode, page)
		}
		if strings.HasPrefix(location.String(), redirectURI) {
			res.Authorization.Redirected = true
			res.Stage = "token"
			return s.CompleteAuthorization(ctx, location.String())
		}
		next = location.String()
	}
	return errors.New("the authorization endpoint redirected more than 5 times")
}
