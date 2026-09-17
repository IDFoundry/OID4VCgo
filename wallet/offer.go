package wallet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo"
)

// ResolveCredentialOffer parses uri's own query parameters (§4.1.2/
// §4.1.3): a credential_offer parameter decodes directly; a
// credential_offer_uri parameter is dereferenced with a hardened,
// SSRF-resistant GET (fapihttp.Client.Fetch), since — per §13.5 — its
// target is untrusted, attacker-reachable input (whatever produced
// uri, such as a scanned QR code). The two parameters are mutually
// exclusive, matching §4.1's own MUST NOT.
//
// The result is not authenticated by this method — see the package
// doc comment's own reminder that a Wallet must never trust an offer
// just because this call succeeded.
func (w *Wallet) ResolveCredentialOffer(ctx context.Context, uri string) (oid4vci.CredentialOffer, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return oid4vci.CredentialOffer{}, fmt.Errorf("wallet: resolve credential offer: parse uri: %w", err)
	}
	q := parsed.Query()
	hasByValue := q.Has("credential_offer")
	hasByRef := q.Has("credential_offer_uri")

	switch {
	case hasByValue && hasByRef:
		return oid4vci.CredentialOffer{}, fmt.Errorf(
			"wallet: resolve credential offer: credential_offer and credential_offer_uri must not both be present")
	case hasByValue:
		return decodeCredentialOffer([]byte(q.Get("credential_offer")))
	case hasByRef:
		return w.fetchCredentialOffer(ctx, q.Get("credential_offer_uri"))
	default:
		return oid4vci.CredentialOffer{}, fmt.Errorf(
			"wallet: resolve credential offer: neither credential_offer nor credential_offer_uri is present")
	}
}

func (w *Wallet) fetchCredentialOffer(ctx context.Context, offerURI string) (oid4vci.CredentialOffer, error) {
	target, err := url.Parse(offerURI)
	if err != nil {
		return oid4vci.CredentialOffer{}, fmt.Errorf("wallet: resolve credential offer: parse credential_offer_uri: %w", err)
	}
	res, err := w.fetcher.Fetch(ctx, fapihttp.FetchRequest{URL: target, ExpectedContentType: "application/json"})
	if err != nil {
		return oid4vci.CredentialOffer{}, fmt.Errorf("wallet: resolve credential offer: fetch credential_offer_uri: %w", err)
	}
	return decodeCredentialOffer(res.Body)
}

func decodeCredentialOffer(raw []byte) (oid4vci.CredentialOffer, error) {
	var offer oid4vci.CredentialOffer
	if err := json.Unmarshal(raw, &offer); err != nil {
		return oid4vci.CredentialOffer{}, fmt.Errorf("wallet: resolve credential offer: decode: %w", err)
	}
	if err := offer.Validate(); err != nil {
		return oid4vci.CredentialOffer{}, fmt.Errorf("wallet: resolve credential offer: %w", err)
	}
	return offer, nil
}
