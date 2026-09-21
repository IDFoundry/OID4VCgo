package oid4vci

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// maxTxCodeDescriptionLength is §4.1.1's own bound on tx_code.description.
const maxTxCodeDescriptionLength = 300

// TxCodeInputMode is a Transaction Code's expected character set
// (§4.1.1's tx_code.input_mode).
type TxCodeInputMode string

const (
	// TxCodeInputModeNumeric restricts a Transaction Code to digits —
	// the default when input_mode is absent.
	TxCodeInputModeNumeric TxCodeInputMode = "numeric"

	// TxCodeInputModeText allows any characters in a Transaction Code.
	TxCodeInputModeText TxCodeInputMode = "text"
)

// TxCode describes the Transaction Code the Authorization Server
// expects alongside a pre-authorized_code Token Request (§4.1.1's
// tx_code) — present (even as an empty object) only when a Transaction
// Code is actually required.
type TxCode struct {
	// InputMode is OPTIONAL; "" means TxCodeInputModeNumeric.
	InputMode TxCodeInputMode `json:"input_mode,omitempty"`

	// Length is OPTIONAL: the expected Transaction Code length, purely
	// to help the Wallet render an input screen. 0 means unspecified.
	Length int `json:"length,omitempty"`

	// Description is OPTIONAL guidance for the End-User on how to
	// obtain the Transaction Code. Must not exceed 300 characters.
	Description string `json:"description,omitempty"`
}

// Validate checks t against §4.1.1's own structural requirements.
func (t TxCode) Validate() error {
	switch t.InputMode {
	case "", TxCodeInputModeNumeric, TxCodeInputModeText:
	default:
		return fmt.Errorf("input_mode must be %q or %q", TxCodeInputModeNumeric, TxCodeInputModeText)
	}
	if t.Length < 0 {
		return fmt.Errorf("length must not be negative")
	}
	if len(t.Description) > maxTxCodeDescriptionLength {
		return fmt.Errorf("description must not exceed %d characters", maxTxCodeDescriptionLength)
	}
	return nil
}

// GrantAuthorizationCode is the "authorization_code" grant a Credential
// Offer's own Grants may declare (§4.1.1).
type GrantAuthorizationCode struct {
	// IssuerState is OPTIONAL: an opaque value the Wallet echoes back
	// as the issuer_state Authorization Request parameter if it uses
	// this grant.
	IssuerState string `json:"issuer_state,omitempty"`

	// AuthorizationServer is OPTIONAL, and only meaningful when the
	// Credential Issuer's own Metadata advertises more than one entry
	// in authorization_servers. Whether that's actually supported is a
	// Credential Issuer's own runtime policy, not a structural fact
	// this type can check on its own.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// GrantPreAuthorizedCode is the
// "urn:ietf:params:oauth:grant-type:pre-authorized_code" grant a
// Credential Offer's own Grants may declare (§4.1.1).
type GrantPreAuthorizedCode struct {
	// PreAuthorizedCode is REQUIRED: a short-lived, single-use code the
	// Wallet presents at the Token Endpoint's Pre-Authorized Code Flow.
	PreAuthorizedCode string `json:"pre-authorized_code"`

	// TxCode is OPTIONAL: present (possibly empty) when the Authorization
	// Server expects a Transaction Code alongside the Token Request.
	TxCode *TxCode `json:"tx_code,omitempty"`

	// AuthorizationServer is OPTIONAL — see
	// GrantAuthorizationCode.AuthorizationServer's own doc comment; the
	// same caveat applies here.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// Validate checks g against §4.1.1's own structural requirements:
// pre-authorized_code is REQUIRED, and TxCode, if present, must itself
// validate. It does not check AuthorizationServer — see its own doc
// comment for why that's a runtime policy question, not a structural
// one.
func (g GrantPreAuthorizedCode) Validate() error {
	if g.PreAuthorizedCode == "" {
		return fmt.Errorf("pre-authorized_code is required")
	}
	if g.TxCode != nil {
		if err := g.TxCode.Validate(); err != nil {
			return fmt.Errorf("tx_code: %w", err)
		}
	}
	return nil
}

// Grants indicates which Grant Types the Wallet may use for a
// Credential Offer (§4.1.1) — nil on CredentialOffer means the Wallet
// must instead determine available grants from the Credential Issuer's
// Metadata. Only the two Grant Types this specification defines are
// supported; at least one must be set when Grants itself is present.
type Grants struct {
	AuthorizationCode *GrantAuthorizationCode `json:"authorization_code,omitempty"`

	// PreAuthorizedCode's JSON key is OID4VCI's own Grant Type
	// identifier URN, not a conventional short name.
	PreAuthorizedCode *GrantPreAuthorizedCode `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

// Validate checks g against §4.1.1's own structural requirements: at
// least one grant type must be set, and PreAuthorizedCode, if present,
// must itself validate.
func (g Grants) Validate() error {
	if g.AuthorizationCode == nil && g.PreAuthorizedCode == nil {
		return fmt.Errorf("must declare at least one grant type when present")
	}
	if g.PreAuthorizedCode != nil {
		if err := g.PreAuthorizedCode.Validate(); err != nil {
			return fmt.Errorf("urn:ietf:params:oauth:grant-type:pre-authorized_code: %w", err)
		}
	}
	return nil
}

// CredentialOffer is the Credential Offer object (§4.1.1) — what a
// Wallet receives either by value (the credential_offer URI query
// parameter) or by reference (fetched from a credential_offer_uri).
//
// A Wallet MUST treat a Credential Offer's contents as untrustworthy:
// its origin is not authenticated and its integrity is not protected
// (§13.5). Validate does not, and cannot, change that — it only checks
// structural well-formedness.
type CredentialOffer struct {
	// CredentialIssuer is REQUIRED: the Credential Issuer's identifier.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialConfigurationIDs is REQUIRED: a non-empty list of
	// unique keys into the Credential Issuer's own
	// credential_configurations_supported metadata.
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`

	// Grants is OPTIONAL — see Grants' own doc comment.
	Grants *Grants `json:"grants,omitempty"`
}

// Validate checks o against §4.1.1's own structural requirements:
// credential_issuer and credential_configuration_ids are non-empty,
// every ID in credential_configuration_ids is unique, and Grants, if
// present, itself validates. It does not check
// credential_configuration_ids against any actual Issuer Metadata —
// that's the caller's own job.
func (o CredentialOffer) Validate() error {
	if o.CredentialIssuer == "" {
		return fmt.Errorf("credential_issuer is required")
	}
	if len(o.CredentialConfigurationIDs) == 0 {
		return fmt.Errorf("credential_configuration_ids must not be empty")
	}
	seen := make(map[string]struct{}, len(o.CredentialConfigurationIDs))
	for _, id := range o.CredentialConfigurationIDs {
		if _, dup := seen[id]; dup {
			return fmt.Errorf("credential_configuration_ids contains duplicate %q", id)
		}
		seen[id] = struct{}{}
	}
	if o.Grants != nil {
		if err := o.Grants.Validate(); err != nil {
			return fmt.Errorf("grants: %w", err)
		}
	}
	return nil
}

// AppendToURL appends o, JSON-encoded, as a by-value "credential_offer"
// query parameter (§4.1.2) to base — the transport-agnostic half of a
// Credential Offer deep link. issuer.Issuer.CreateCredentialOffer
// already builds one flavor of this (the "openid-credential-offer://"
// custom scheme a real Wallet registers to handle), but a caller
// without a live *Issuer to hand — delivering an offer to a fixed test
// endpoint, or one round-tripped through storage rather than freshly
// built — needs the same transform against a base of its own choosing,
// which may already carry a query string. base is used as-is,
// otherwise; this does no scheme/URL validation of its own.
func (o CredentialOffer) AppendToURL(base string) (string, error) {
	encoded, err := json.Marshal(o)
	if err != nil {
		return "", fmt.Errorf("oid4vci: credential offer: encode: %w", err)
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + "credential_offer=" + url.QueryEscape(string(encoded)), nil
}
