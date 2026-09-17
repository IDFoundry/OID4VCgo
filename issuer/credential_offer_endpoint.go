package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/idfoundry/oid4vcgo"
)

// credentialOfferReferenceEntropyBytes sets how much randomness backs
// a by-reference offer's Reference. 256 bits, matching this package's
// own c_nonce entropy choice (see nonceEntropyBytes) and FAPIgo's
// request_uri reference.
const credentialOfferReferenceEntropyBytes = 32

// credentialOfferScheme is the custom URI scheme a Wallet registers to
// handle a Credential Offer deep link (§4.1.2, Appendix G.7.1).
const credentialOfferScheme = "openid-credential-offer://" //nolint:gosec // a URI scheme, not a credential

// CreateCredentialOfferRequest is the input to CreateCredentialOffer.
type CreateCredentialOfferRequest struct {
	// CredentialConfigurationIDs is REQUIRED — see
	// oid4vci.CredentialOffer.CredentialConfigurationIDs' own doc comment.
	CredentialConfigurationIDs []string

	// Grants is OPTIONAL — see oid4vci.Grants' own doc comment.
	Grants *oid4vci.Grants

	// ByReference, when true, has CreateCredentialOffer store the
	// offer and return a credential_offer_uri reference (§4.1.3)
	// instead of embedding it by value — appropriate for a QR code,
	// where a by-value offer's size is often impractical. Requires
	// Config.CredentialOfferEndpoint and Dependencies.CredentialOffers
	// to be configured.
	ByReference bool
}

// CredentialOfferResult is returned by a successful CreateCredentialOffer.
type CredentialOfferResult struct {
	// Offer is the Credential Offer object itself.
	Offer oid4vci.CredentialOffer

	// URI is the complete deep-link URI (the openid-credential-offer
	// custom scheme, §4.1.2) a caller can render as a link or encode
	// into a QR code. It carries either a credential_offer (by value)
	// or credential_offer_uri (by reference) query parameter, matching
	// whether CreateCredentialOfferRequest.ByReference was set.
	URI string

	// Reference is the opaque lookup key GetCredentialOffer accepts —
	// set only when ByReference was requested, "" otherwise. URI
	// already embeds this value; Reference is exposed separately for
	// a caller that wants to log or revoke a stored offer without
	// re-parsing URI.
	Reference string
}

// CreateCredentialOffer builds a Credential Offer (§4.1) from req,
// validates it against Config, and returns it either embedded by value
// in a deep-link URI or, when req.ByReference is set, stored and
// referenced by a credential_offer_uri deep-link URI.
//
// This package has no Authorization or Token Endpoint yet (see
// ARCHITECTURE.md): a pre-authorized_code grant's own code, and an
// authorization_code grant's own issuer_state, are caller-supplied —
// generating and later redeeming them is that future endpoint's job,
// not this method's.
func (iss *Issuer) CreateCredentialOffer(ctx context.Context, req CreateCredentialOfferRequest) (CredentialOfferResult, error) {
	offer := oid4vci.CredentialOffer{
		CredentialIssuer:           iss.cfg.Issuer.String(),
		CredentialConfigurationIDs: req.CredentialConfigurationIDs,
		Grants:                     req.Grants,
	}
	if err := validateCredentialOffer(offer, iss.cfg); err != nil {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create credential offer: %w", err)
	}

	if !req.ByReference {
		uri, err := credentialOfferURIByValue(offer)
		if err != nil {
			return CredentialOfferResult{}, fmt.Errorf("issuer: create credential offer: %w", err)
		}
		return CredentialOfferResult{Offer: offer, URI: uri}, nil
	}
	return iss.createCredentialOfferByReference(ctx, offer)
}

func (iss *Issuer) createCredentialOfferByReference(ctx context.Context, offer oid4vci.CredentialOffer) (CredentialOfferResult, error) {
	if iss.cfg.CredentialOfferEndpoint.IsZero() {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create credential offer: credential_offer_endpoint is not configured")
	}

	reference, err := iss.generateCredentialOfferReference()
	if err != nil {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create credential offer: %w", err)
	}

	now := iss.deps.Clock.Now()
	if err := iss.deps.CredentialOffers.Store(ctx, CredentialOfferRecord{
		Reference: reference,
		Offer:     offer,
		ExpiresAt: now.Add(iss.cfg.Limits.CredentialOfferLifetime),
	}); err != nil {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create credential offer: persist offer: %w", err)
	}

	base := iss.cfg.CredentialOfferEndpoint.URL()
	offerURL := (&base).JoinPath(reference).String()
	uri := credentialOfferScheme + "?credential_offer_uri=" + url.QueryEscape(offerURL)
	return CredentialOfferResult{Offer: offer, URI: uri, Reference: reference}, nil
}

func credentialOfferURIByValue(offer oid4vci.CredentialOffer) (string, error) {
	encoded, err := json.Marshal(offer)
	if err != nil {
		return "", fmt.Errorf("encode credential offer: %w", err)
	}
	return credentialOfferScheme + "?credential_offer=" + url.QueryEscape(string(encoded)), nil
}

func (iss *Issuer) generateCredentialOfferReference() (string, error) {
	raw := make([]byte, credentialOfferReferenceEntropyBytes)
	if _, err := io.ReadFull(iss.deps.Random, raw); err != nil {
		return "", fmt.Errorf("generate reference: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// GetCredentialOffer retrieves a previously stored Credential Offer by
// its Reference (CredentialOfferResult.Reference, or the last path
// segment of the credential_offer_uri CreateCredentialOffer returned)
// — the domain logic behind the HTTP GET request §4.1.3 has the Wallet
// make when dereferencing a by-reference offer. Returns an error if
// reference is unknown or has expired.
func (iss *Issuer) GetCredentialOffer(ctx context.Context, reference string) (oid4vci.CredentialOffer, error) {
	if iss.deps.CredentialOffers == nil {
		return oid4vci.CredentialOffer{}, fmt.Errorf("issuer: get credential offer: credential offers are not configured")
	}
	record, err := iss.deps.CredentialOffers.Get(ctx, reference)
	if err != nil {
		return oid4vci.CredentialOffer{}, fmt.Errorf("issuer: get credential offer: %w", err)
	}
	if !iss.deps.Clock.Now().Before(record.ExpiresAt) {
		return oid4vci.CredentialOffer{}, fmt.Errorf("issuer: get credential offer: reference has expired")
	}
	return record.Offer, nil
}

// WriteCredentialOfferJSON writes offer as a Credential Offer Object
// response to w (§4.1.3: "The response from the Credential Issuer that
// contains a Credential Offer Object MUST use the media type
// application/json") — what an HTTP adapter's GET handler for
// Config.CredentialOfferEndpoint calls after a successful
// GetCredentialOffer. Must be called before anything else writes to w.
func WriteCredentialOfferJSON(w http.ResponseWriter, offer oid4vci.CredentialOffer) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(offer)
}
