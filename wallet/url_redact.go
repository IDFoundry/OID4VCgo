package wallet

import (
	"net/url"
	"strconv"
	"strings"
)

// Placeholders for the URLs the wallet keeps out of its errors. Each
// URL is a capability, and errors end up in logs: anyone who could read
// them could use it.
const (
	// redactedOfferLink is a Credential Offer link, which may carry an
	// offer by value, pre-authorized code and all.
	redactedOfferLink = "(the offer link)"
	// redactedOfferURI is a by-reference offer's credential_offer_uri,
	// which serves the offer, pre-authorized code and all, until the
	// issuer retires it.
	redactedOfferURI = "(the credential_offer_uri)"
	// redactedRequestLink is an OpenID4VP invocation link, and
	// redactedRequestURI its request_uri, which serves the Verifier's
	// Request Object.
	redactedRequestLink = "(the request link)"
	redactedRequestURI  = "(the request_uri)"
)

// redactURLs is err with the URL of every *url.Error in its tree —
// which http.Client.Do and url.Parse quote whole, path and query
// included — replaced by placeholder, in its text and in the
// *url.Error that errors.As finds. Every cause stays: errors.Is and
// errors.As find what they found before (a timeout, a refused address,
// the *url.Error's Op), except that a wrapper between err and a
// *url.Error is no longer its own type. An err with no *url.Error is
// returned as it is.
func redactURLs(err error, placeholder string) error {
	var urls []string
	collectURLs(err, &urls)
	if len(urls) == 0 {
		return err
	}
	replacements := make([]string, 0, 4*len(urls))
	for _, u := range urls {
		// url.Error formats its URL with %q: replace that first, then
		// any copy a wrapper wrote out unquoted.
		replacements = append(replacements, strconv.Quote(u), strconv.Quote(placeholder))
		replacements = append(replacements, u, placeholder)
	}
	r := strings.NewReplacer(replacements...)
	redacted, _ := rebuild(err, placeholder, r)
	return redacted
}

// collectURLs appends the URL of every *url.Error in err's tree that
// isn't empty.
func collectURLs(err error, urls *[]string) {
	if err == nil {
		return
	}
	if ue, ok := err.(*url.Error); ok && ue.URL != "" {
		*urls = append(*urls, ue.URL)
	}
	switch e := err.(type) {
	case interface{ Unwrap() error }:
		collectURLs(e.Unwrap(), urls)
	case interface{ Unwrap() []error }:
		for _, child := range e.Unwrap() {
			collectURLs(child, urls)
		}
	}
}

// rebuild is redactURLs' copy of err's tree, and whether it differs:
// each *url.Error copied with placeholder for its URL, each wrapper
// above one a redactedError whose text r has rewritten, and every other
// subtree kept as it is.
func rebuild(err error, placeholder string, r *strings.Replacer) (error, bool) {
	if err == nil {
		return nil, false
	}
	if ue, ok := err.(*url.Error); ok {
		cp := *ue
		cp.URL = placeholder
		cp.Err, _ = rebuild(ue.Err, placeholder, r)
		return &cp, true
	}
	var children []error
	switch e := err.(type) {
	case interface{ Unwrap() error }:
		children = []error{e.Unwrap()}
	case interface{ Unwrap() []error }:
		children = e.Unwrap()
	default:
		return err, false
	}
	changed := false
	rebuilt := make([]error, len(children))
	for i, child := range children {
		var c bool
		rebuilt[i], c = rebuild(child, placeholder, r)
		changed = changed || c
	}
	if !changed {
		return err, false
	}
	return &redactedError{msg: r.Replace(err.Error()), errs: rebuilt}, true
}

// redactedError stands for a wrapper whose tree held a URL: its text
// with the URL replaced, over the redacted causes.
type redactedError struct {
	msg  string
	errs []error
}

func (e *redactedError) Error() string   { return e.msg }
func (e *redactedError) Unwrap() []error { return e.errs }
