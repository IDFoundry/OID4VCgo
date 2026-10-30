package issuer

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/idfoundry/oid4vcgo"
)

// preAuthorizedCodeBytes is a generated pre-authorized_code's entropy:
// 256 bits, as for any bearer credential a Wallet presents once.
const preAuthorizedCodeBytes = 32

// CreatePreAuthorizedOfferRequest is a Credential Offer with a
// pre-authorized code grant (§4.1.1, §6.1), for
// CreatePreAuthorizedOffer.
type CreatePreAuthorizedOfferRequest struct {
	// CredentialConfigurationIDs are the offered configurations.
	// REQUIRED.
	CredentialConfigurationIDs []string

	// Scopes are what the code's access token grants
	// (PreAuthorizedCodeRecord.Scopes).
	Scopes []string

	// CredentialIdentifiers mints a credential_identifier per offered
	// configuration at redemption, returned as authorization_details
	// (PreAuthorizedCodeRecord.CredentialConfigurationIDs).
	CredentialIdentifiers bool

	// Subject is whose Credential the code redeems for
	// (PreAuthorizedCodeRecord.Subject): opaque and unguessable.
	Subject string

	// TxCode, when set, is the Transaction Code (a PIN) the holder must
	// enter to redeem the code, sent to them out of band. The offer's
	// tx_code object is derived from it: numeric input mode when it's
	// all digits, and its length.
	TxCode string

	// TxCodeDescription, OPTIONAL, tells the holder where to find the
	// Transaction Code (§4.1.1: at most 300 characters).
	TxCodeDescription string

	// Lifetime bounds how long the code stays redeemable. REQUIRED.
	Lifetime time.Duration

	// AuthorizationServer, OPTIONAL, names the Authorization Server
	// that redeems the code, when the issuer lists more than one.
	AuthorizationServer string

	// ByReference publishes the offer at the Credential Offer Endpoint
	// rather than in the URI itself (CreateCredentialOfferRequest).
	// Dependencies.CredentialOffers then holds the offer, the code in
	// it included, until Limits.CredentialOfferLifetime passes: unlike
	// Dependencies.PreAuthorizedCodes, which holds only its hash.
	ByReference bool
}

// CreatePreAuthorizedOffer creates a Credential Offer with a
// pre-authorized code grant in one step: it generates a 256-bit
// pre-authorized_code from Dependencies.Random, stores its record with
// Dependencies.PreAuthorizedCodes, and builds the offer, its tx_code
// object derived from the record's Transaction Code. Prefer it to
// issuing a code and calling CreateCredentialOffer separately: there,
// an offer that asks for a Transaction Code while its record holds none
// is redeemed without one, and a weak code is accepted.
func (iss *Issuer) CreatePreAuthorizedOffer(ctx context.Context, req CreatePreAuthorizedOfferRequest) (CredentialOfferResult, error) {
	switch {
	case iss.deps.PreAuthorizedCodes == nil:
		return CredentialOfferResult{}, errors.New("issuer: create pre-authorized offer: dependencies.pre_authorized_codes is not set")
	case len(req.CredentialConfigurationIDs) == 0:
		return CredentialOfferResult{}, errors.New("issuer: create pre-authorized offer: credential_configuration_ids is required")
	case req.Lifetime <= 0:
		return CredentialOfferResult{}, errors.New("issuer: create pre-authorized offer: lifetime must be positive")
	case req.Subject == "":
		// Every holder redeemed without one would share sub "".
		return CredentialOfferResult{}, errors.New("issuer: create pre-authorized offer: subject is required")
	}
	if err := iss.checkPreAuthorizedGrant(req); err != nil {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create pre-authorized offer: %w", err)
	}
	grant := &oid4vci.GrantPreAuthorizedCode{AuthorizationServer: req.AuthorizationServer}
	if req.TxCode != "" {
		grant.TxCode = txCodeFor(req.TxCode, req.TxCodeDescription)
	} else if req.TxCodeDescription != "" {
		return CredentialOfferResult{}, errors.New("issuer: create pre-authorized offer: tx_code_description without a tx_code")
	}
	code, err := randomID(iss.deps.Random, preAuthorizedCodeBytes)
	if err != nil {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create pre-authorized offer: generate code: %w", err)
	}
	grant.PreAuthorizedCode = code
	req.CredentialConfigurationIDs = append([]string(nil), req.CredentialConfigurationIDs...)
	offerReq := CreateCredentialOfferRequest{
		CredentialConfigurationIDs: req.CredentialConfigurationIDs,
		Grants:                     &oid4vci.Grants{PreAuthorizedCode: grant},
		ByReference:                req.ByReference,
	}
	// Checked before the code is stored, so a refused offer leaves no
	// redeemable code behind.
	offer := oid4vci.CredentialOffer{CredentialIssuer: iss.cfg.Issuer.String(), CredentialConfigurationIDs: offerReq.CredentialConfigurationIDs, Grants: offerReq.Grants}
	if err := validateCredentialOffer(offer, iss.cfg); err != nil {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create pre-authorized offer: %w", err)
	}
	record := PreAuthorizedCodeRecord{
		Scopes: req.Scopes, Subject: req.Subject,
		ExpiresAt: iss.deps.Clock.Now().Add(req.Lifetime),
	}
	if req.CredentialIdentifiers {
		record.CredentialConfigurationIDs = req.CredentialConfigurationIDs
	}
	if err := iss.storePreAuthorizedCode(ctx, code, req.TxCode, record); err != nil {
		return CredentialOfferResult{}, fmt.Errorf("issuer: create pre-authorized offer: store code: %w", err)
	}
	return iss.createCredentialOffer(ctx, offerReq)
}

// IssuePreAuthorizedCode stores record for a pre-authorized_code the
// caller generated itself, with txCode, when set, as the Transaction
// Code the holder must enter to redeem it. The store receives a hash of
// code and record.TxCodeHash set from txCode, never either value; leave
// TxCodeHash empty. The caller builds the Credential Offer carrying
// code with CreateCredentialOffer, its tx_code object matching txCode.
//
// It's for development and tests, where a fixed code is convenient:
// under AssuranceProduction it's refused, as CreateCredentialOffer
// refuses a pre-authorized grant there, so that a code's offer and
// record can't disagree. Use CreatePreAuthorizedOffer.
func (iss *Issuer) IssuePreAuthorizedCode(ctx context.Context, code, txCode string, record PreAuthorizedCodeRecord) error {
	switch {
	case iss.cfg.Assurance == AssuranceProduction:
		return errors.New("issuer: issue pre-authorized code: refused under AssuranceProduction: use CreatePreAuthorizedOffer")
	case iss.deps.PreAuthorizedCodes == nil:
		return errors.New("issuer: issue pre-authorized code: dependencies.pre_authorized_codes is not set")
	case code == "":
		return errors.New("issuer: issue pre-authorized code: code is required")
	case record.TxCodeHash != "":
		return errors.New("issuer: issue pre-authorized code: pass the Transaction Code as txCode, not record.TxCodeHash")
	}
	if err := iss.storePreAuthorizedCode(ctx, code, txCode, record); err != nil {
		return fmt.Errorf("issuer: issue pre-authorized code: %w", err)
	}
	return nil
}

// storePreAuthorizedCode stores record under code's hash, with txCode's
// hash as its TxCodeHash.
func (iss *Issuer) storePreAuthorizedCode(ctx context.Context, code, txCode string, record PreAuthorizedCodeRecord) error {
	record.TxCodeHash = txCodeHash(code, txCode)
	return iss.deps.PreAuthorizedCodes.Issue(ctx, preAuthorizedCodeKey(code), record)
}

// txCodeFor is the offer's tx_code object for txCode: numeric input
// when it's all digits, and its length in characters.
func txCodeFor(txCode, description string) *oid4vci.TxCode {
	mode := oid4vci.TxCodeInputModeNumeric
	for _, r := range txCode {
		if r < '0' || r > '9' {
			mode = oid4vci.TxCodeInputModeText
			break
		}
	}
	return &oid4vci.TxCode{InputMode: mode, Length: utf8.RuneCountInString(txCode), Description: description}
}

// MinProductionTxCodeLength and MaxProductionPreAuthorizedLifetime bound
// a pre-authorized offer under AssuranceProduction: a shorter
// Transaction Code is guessed within Limits.MaxTxCodeAttempts too
// often (a one-digit code, half the time in 5 tries), and a code meant
// to be short-lived (OpenID4VCI §3.5) shouldn't outlast a week.
// MaxProductionTxCodeAttempts bounds Limits.MaxTxCodeAttempts under
// AssuranceProduction, so the shortest code allowed stays hard to
// guess: at most 10 tries against a six-digit code succeed one time in
// 100,000.
const (
	MinProductionTxCodeLength          = 6
	MaxProductionPreAuthorizedLifetime = 7 * 24 * time.Hour
	MaxProductionTxCodeAttempts        = 10
)

// checkPreAuthorizedGrant refuses a pre-authorized offer whose code's
// token wouldn't grant what it offers, by scope or credential
// identifiers: the code would be spent when the holder redeemed it,
// and every Credential Request then refused. Under AssuranceProduction
// it also bounds the Transaction Code and the code's lifetime.
func (iss *Issuer) checkPreAuthorizedGrant(req CreatePreAuthorizedOfferRequest) error {
	for _, id := range req.CredentialConfigurationIDs {
		cc := iss.cfg.CredentialConfigurationsSupported[id]
		if !req.CredentialIdentifiers && (cc.Scope == "" || !slices.Contains(req.Scopes, cc.Scope)) {
			return fmt.Errorf("the code wouldn't grant %q: give scopes including its scope, or set credential_identifiers", id)
		}
	}
	if iss.cfg.Assurance != AssuranceProduction {
		return nil
	}
	if req.TxCode != "" && utf8.RuneCountInString(req.TxCode) < MinProductionTxCodeLength {
		return fmt.Errorf("tx_code must be at least %d characters under AssuranceProduction", MinProductionTxCodeLength)
	}
	if req.Lifetime > MaxProductionPreAuthorizedLifetime {
		return fmt.Errorf("lifetime %s is over the %s allowed under AssuranceProduction", req.Lifetime, MaxProductionPreAuthorizedLifetime)
	}
	return nil
}
