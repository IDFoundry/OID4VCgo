package main

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
)

// maxLoginSteps bounds the pages and redirects login follows.
const maxLoginSteps = 10

// maxPageBytes bounds a login page.
const maxPageBytes = 1 << 20

// login stands in for the holder's browser at the authorization
// endpoint: it opens authURL, signs user in on the Authorization
// Server's (Keycloak's) login form, and follows redirects until one
// goes to redirectURI, which it returns, without following it. base
// supplies the TLS configuration; login keeps its own cookies.
func login(ctx context.Context, base *http.Client, authURL, redirectURI, user, password string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	browser := &http.Client{
		Transport:     base.Transport,
		Jar:           jar,
		Timeout:       base.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return "", err
	}
	submitted := false
	for range maxLoginSteps {
		res, err := browser.Do(req)
		if err != nil {
			return "", err
		}
		page, err := io.ReadAll(io.LimitReader(res.Body, maxPageBytes+1))
		_ = res.Body.Close()
		if err != nil {
			return "", err
		}
		if len(page) > maxPageBytes {
			return "", fmt.Errorf("login: the page at %s exceeds %d bytes", res.Request.URL.Redacted(), maxPageBytes)
		}
		switch {
		case res.StatusCode >= 300 && res.StatusCode < 400:
			next, err := res.Request.URL.Parse(res.Header.Get("Location"))
			if err != nil {
				return "", fmt.Errorf("login: redirect: %w", err)
			}
			if strings.HasPrefix(next.String(), redirectURI) {
				return next.String(), nil
			}
			if req, err = http.NewRequestWithContext(ctx, http.MethodGet, next.String(), nil); err != nil {
				return "", err
			}
		case res.StatusCode == http.StatusOK && !submitted:
			action, err := loginFormAction(string(page), res.Request.URL)
			if err != nil {
				return "", err
			}
			form := url.Values{"username": {user}, "password": {password}, "credentialId": {""}}
			if req, err = http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(form.Encode())); err != nil {
				return "", err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			submitted = true
		default:
			return "", fmt.Errorf("login: %s answered %d: %s", res.Request.URL.Path, res.StatusCode, pageText(string(page)))
		}
	}
	return "", errors.New("login: too many pages and redirects")
}

var (
	loginForm  = regexp.MustCompile(`(?is)<form\b[^>]*\bid="kc-form-login"[^>]*>`)
	formAction = regexp.MustCompile(`(?is)\baction="([^"]*)"`)
)

// loginFormAction is the URL Keycloak's login form posts to, resolved
// against page's own URL.
func loginFormAction(page string, base *url.URL) (string, error) {
	tag := loginForm.FindString(page)
	if tag == "" {
		return "", fmt.Errorf("login: no login form on the page: %s", pageText(page))
	}
	m := formAction.FindStringSubmatch(tag)
	if m == nil {
		return "", errors.New("login: the login form has no action")
	}
	action, err := base.Parse(html.UnescapeString(m[1]))
	if err != nil {
		return "", fmt.Errorf("login: form action: %w", err)
	}
	if action.Scheme != "https" || action.Host != base.Host {
		return "", fmt.Errorf("login: the login form posts to another origin, %s", action.Host)
	}
	return action.String(), nil
}

var (
	tags       = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]*>`)
	whitespace = regexp.MustCompile(`\s+`)
)

// pageText is the start of an HTML page's text, for an error message.
func pageText(page string) string {
	text := strings.TrimSpace(whitespace.ReplaceAllString(html.UnescapeString(tags.ReplaceAllString(page, " ")), " "))
	if len(text) > 200 {
		text = text[:200]
	}
	return text
}
