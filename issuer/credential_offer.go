package issuer

import "fmt"

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

func (t TxCode) validate() error {
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

	// AuthorizationServer is OPTIONAL, and only meaningful when this
	// issuer's own Metadata advertises more than one entry in
	// authorization_servers — which this package does not support yet
	// (see ARCHITECTURE.md), so validate rejects any non-empty value.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

func (g GrantAuthorizationCode) validate() error {
	if g.AuthorizationServer != "" {
		return fmt.Errorf("authorization_server must not be set: this issuer's metadata does not advertise multiple authorization_servers")
	}
	return nil
}

// GrantPreAuthorizedCode is the
// "urn:ietf:params:oauth:grant-type:pre-authorized_code" grant a
// Credential Offer's own Grants may declare (§4.1.1).
type GrantPreAuthorizedCode struct {
	// PreAuthorizedCode is REQUIRED: a short-lived, single-use code the
	// Wallet presents at the Token Endpoint's Pre-Authorized Code Flow.
	// This package treats it as caller-supplied opaque data — issuing
	// and later redeeming it is the Token Endpoint's job, which doesn't
	// exist in this repo yet (see ARCHITECTURE.md).
	PreAuthorizedCode string `json:"pre-authorized_code"`

	// TxCode is OPTIONAL: present (possibly empty) when the Authorization
	// Server expects a Transaction Code alongside the Token Request.
	TxCode *TxCode `json:"tx_code,omitempty"`

	// AuthorizationServer is OPTIONAL — see
	// GrantAuthorizationCode.AuthorizationServer's own doc comment;
	// the same restriction applies here.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

func (g GrantPreAuthorizedCode) validate() error {
	if g.PreAuthorizedCode == "" {
		return fmt.Errorf("pre-authorized_code is required")
	}
	if g.AuthorizationServer != "" {
		return fmt.Errorf("authorization_server must not be set: this issuer's metadata does not advertise multiple authorization_servers")
	}
	if g.TxCode != nil {
		if err := g.TxCode.validate(); err != nil {
			return fmt.Errorf("tx_code: %w", err)
		}
	}
	return nil
}

// Grants indicates which Grant Types the Wallet may use for a
// Credential Offer (§4.1.1) — nil on CredentialOffer means the Wallet
// must instead determine available grants from this issuer's
// Metadata. Only the two Grant Types this specification defines are
// supported; at least one must be set when Grants itself is present.
type Grants struct {
	AuthorizationCode *GrantAuthorizationCode `json:"authorization_code,omitempty"`

	// PreAuthorizedCode's JSON key is OID4VCI's own Grant Type
	// identifier URN, not a conventional short name.
	PreAuthorizedCode *GrantPreAuthorizedCode `json:"urn:ietf:params:oauth:grant-type:pre-authorized_code,omitempty"`
}

func (g Grants) validate() error {
	if g.AuthorizationCode == nil && g.PreAuthorizedCode == nil {
		return fmt.Errorf("must declare at least one grant type when present")
	}
	if g.AuthorizationCode != nil {
		if err := g.AuthorizationCode.validate(); err != nil {
			return fmt.Errorf("authorization_code: %w", err)
		}
	}
	if g.PreAuthorizedCode != nil {
		if err := g.PreAuthorizedCode.validate(); err != nil {
			return fmt.Errorf("urn:ietf:params:oauth:grant-type:pre-authorized_code: %w", err)
		}
	}
	return nil
}

// CredentialOffer is the Credential Offer object (§4.1.1) — what a
// Wallet receives either by value (the credential_offer URI query
// parameter) or by reference (fetched from a credential_offer_uri).
type CredentialOffer struct {
	// CredentialIssuer is this Credential Issuer's identifier —
	// CreateCredentialOffer always sets it from Config.Issuer.
	CredentialIssuer string `json:"credential_issuer"`

	// CredentialConfigurationIDs is REQUIRED: a non-empty list of
	// unique keys into Config.CredentialConfigurationsSupported.
	CredentialConfigurationIDs []string `json:"credential_configuration_ids"`

	// Grants is OPTIONAL — see Grants' own doc comment.
	Grants *Grants `json:"grants,omitempty"`
}

// validate checks o against §4.1.1's own requirements and, where this
// package's own scope narrows a spec-optional value (AuthorizationServer),
// against what cfg actually supports.
func (o CredentialOffer) validate(cfg Config) error {
	if len(o.CredentialConfigurationIDs) == 0 {
		return fmt.Errorf("credential_configuration_ids must not be empty")
	}
	seen := make(map[string]struct{}, len(o.CredentialConfigurationIDs))
	for _, id := range o.CredentialConfigurationIDs {
		if _, dup := seen[id]; dup {
			return fmt.Errorf("credential_configuration_ids contains duplicate %q", id)
		}
		seen[id] = struct{}{}
		if _, ok := cfg.CredentialConfigurationsSupported[id]; !ok {
			return fmt.Errorf("credential_configuration_ids contains unknown id %q", id)
		}
	}
	if o.Grants != nil {
		if err := o.Grants.validate(); err != nil {
			return fmt.Errorf("grants: %w", err)
		}
	}
	return nil
}
