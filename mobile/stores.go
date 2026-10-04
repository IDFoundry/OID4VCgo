package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// CredentialStore holds the wallet's credentials for it — under the
// platform's data protection — as opaque JSON records the app keeps by
// ID.
type CredentialStore interface {
	// Put stores record under id, replacing any record with that ID.
	Put(id string, record []byte) error
	// Get returns id's record — empty, with no error, when there's none.
	Get(id string) ([]byte, error)
	// List returns every record, as a JSON array of them.
	List() ([]byte, error)
	// Delete deletes id's record. Deleting one that doesn't exist isn't
	// an error.
	Delete(id string) error
	// Durable reports whether records survive the app quitting.
	// Receiving credentials needs a durable CredentialStore unless the
	// wallet is configured for development: it also keeps the
	// authorization in progress while the holder is at the issuer's
	// pages.
	Durable() bool
}

// WalletProvider asks the Wallet Provider's backend for attestations
// (HAIP 1.0 §4.4.1, §4.5.1). Keys are public JWKs; attestations are
// compact JWTs.
type WalletProvider interface {
	// WalletAttestation returns a Wallet Attestation binding the
	// instance key instanceKeyJWK to clientID.
	WalletAttestation(clientID string, instanceKeyJWK []byte) ([]byte, error)
	// KeyAttestation returns a Key Attestation over keysJWK, a JSON
	// array of JWKs, carrying the issuer's nonce.
	KeyAttestation(keysJWK []byte, nonce string) ([]byte, error)
}

// credentialRecord is a stored credential, as the CredentialStore keeps
// it: this package's format, versioned with ABIVersion.
type credentialRecord struct {
	ID               string    `json:"id"`
	CredentialIssuer string    `json:"credential_issuer"`
	ConfigurationID  string    `json:"configuration_id"`
	Format           string    `json:"format"`
	VCT              string    `json:"vct,omitempty"`
	DocType          string    `json:"doctype,omitempty"`
	Credential       string    `json:"credential"`
	HolderKeyID      string    `json:"holder_key_id"`
	ReceivedAt       time.Time `json:"received_at"`
	// Claims are the credential's claims for display, as JSON (see
	// jsonClaims); absent from a record written before they were kept.
	Claims json.RawMessage `json:"claims,omitempty"`
	// Display, ValidUntil, StatusList and Status: absent from a record
	// written before they were kept.
	Display       *displayJSON    `json:"display,omitempty"`
	Copies        []copyJSON      `json:"copies,omitempty"`
	ValidUntil    *time.Time      `json:"valid_until,omitempty"`
	StatusList    *statusListJSON `json:"status_list,omitempty"`
	StatusListCWT bool            `json:"status_list_cwt,omitempty"`
	Status        *statusJSON     `json:"status,omitempty"`
	GrantID       string          `json:"grant_id,omitempty"`
}

// copyJSON is a walletflow.CredentialCopy.
type copyJSON struct {
	Credential  string   `json:"credential"`
	HolderKeyID string   `json:"holder_key_id"`
	Presented   bool     `json:"presented,omitempty"`
	ShownTo     []string `json:"shown_to,omitempty"`
}

// logoJSON is a walletflow.Logo.
type logoJSON struct {
	URI     string `json:"uri"`
	AltText string `json:"alt_text,omitempty"`
}

func logoOf(l *walletflow.Logo) *logoJSON {
	if l == nil {
		return nil
	}
	return &logoJSON{URI: l.URI, AltText: l.AltText}
}

func (l *logoJSON) logo() *walletflow.Logo {
	if l == nil {
		return nil
	}
	return &walletflow.Logo{URI: l.URI, AltText: l.AltText}
}

// displayJSON is a walletflow.Display.
type displayJSON struct {
	IssuerName      string    `json:"issuer_name,omitempty"`
	IssuerLogo      *logoJSON `json:"issuer_logo,omitempty"`
	Name            string    `json:"name,omitempty"`
	Description     string    `json:"description,omitempty"`
	Logo            *logoJSON `json:"logo,omitempty"`
	BackgroundColor string    `json:"background_color,omitempty"`
	TextColor       string    `json:"text_color,omitempty"`
}

func displayOf(d walletflow.Display) *displayJSON {
	if d == (walletflow.Display{}) {
		return nil
	}
	return &displayJSON{
		IssuerName: d.IssuerName, IssuerLogo: logoOf(d.IssuerLogo), Name: d.Name, Description: d.Description,
		Logo: logoOf(d.Logo), BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
	}
}

func (d *displayJSON) display() walletflow.Display {
	if d == nil {
		return walletflow.Display{}
	}
	return walletflow.Display{
		IssuerName: d.IssuerName, IssuerLogo: d.IssuerLogo.logo(), Name: d.Name, Description: d.Description,
		Logo: d.Logo.logo(), BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
	}
}

// statusListJSON is a credential's status list reference.
type statusListJSON struct {
	Idx uint64 `json:"idx"`
	URI string `json:"uri"`
}

// statusJSON is a walletflow.CredentialStatus.
type statusJSON struct {
	Value     string    `json:"value"`
	CheckedAt time.Time `json:"checked_at"`
}

func recordOf(c walletflow.StoredCredential) (credentialRecord, error) {
	r := credentialRecord{
		ID: c.ID, CredentialIssuer: c.CredentialIssuer, ConfigurationID: c.ConfigurationID, Format: c.Format,
		VCT: c.VCT, DocType: c.DocType, Credential: c.Credential, HolderKeyID: c.HolderKeyID, ReceivedAt: c.ReceivedAt,
		Display: displayOf(c.Display), StatusListCWT: c.StatusListCWT, GrantID: c.GrantID,
	}
	for _, cp := range c.Copies {
		r.Copies = append(r.Copies, copyJSON{Credential: cp.Credential, HolderKeyID: cp.HolderKeyID, Presented: cp.Presented, ShownTo: cp.ShownTo})
	}
	if !c.ValidUntil.IsZero() {
		r.ValidUntil = &c.ValidUntil
	}
	if c.StatusList != nil {
		r.StatusList = &statusListJSON{Idx: c.StatusList.Idx, URI: c.StatusList.URI}
	}
	if c.Status.Value != "" {
		r.Status = &statusJSON{Value: c.Status.Value, CheckedAt: c.Status.CheckedAt}
	}
	if c.Claims != nil {
		raw, err := json.Marshal(jsonClaims(c.Claims))
		if err != nil {
			return credentialRecord{}, err
		}
		r.Claims = raw
	}
	return r, nil
}

func (r credentialRecord) stored() (walletflow.StoredCredential, error) {
	c := walletflow.StoredCredential{
		ID: r.ID, CredentialIssuer: r.CredentialIssuer, ConfigurationID: r.ConfigurationID, Format: r.Format,
		VCT: r.VCT, DocType: r.DocType, Credential: r.Credential, HolderKeyID: r.HolderKeyID, ReceivedAt: r.ReceivedAt,
		Display: r.Display.display(), StatusListCWT: r.StatusListCWT, GrantID: r.GrantID,
	}
	for _, cp := range r.Copies {
		c.Copies = append(c.Copies, walletflow.CredentialCopy{Credential: cp.Credential, HolderKeyID: cp.HolderKeyID, Presented: cp.Presented, ShownTo: cp.ShownTo})
	}
	if r.ValidUntil != nil {
		c.ValidUntil = *r.ValidUntil
	}
	if r.StatusList != nil {
		c.StatusList = &statuslist.StatusListRef{Idx: r.StatusList.Idx, URI: r.StatusList.URI}
	}
	if r.Status != nil {
		c.Status = walletflow.CredentialStatus{Value: r.Status.Value, CheckedAt: r.Status.CheckedAt}
	}
	if len(r.Claims) > 0 {
		if err := json.Unmarshal(r.Claims, &c.Claims); err != nil {
			return walletflow.StoredCredential{}, err
		}
	}
	return c, nil
}

// credentialSummary is a credential as the app lists it: everything but
// the credential itself, its key and its claims.
type credentialSummary struct {
	ID               string    `json:"id"`
	CredentialIssuer string    `json:"credential_issuer"`
	ConfigurationID  string    `json:"configuration_id"`
	Format           string    `json:"format"`
	VCT              string    `json:"vct,omitempty"`
	DocType          string    `json:"doctype,omitempty"`
	ReceivedAt       time.Time `json:"received_at"`
	// Display is how to show it, from the issuer's metadata; ValidUntil
	// when it expires; Status its revocation status as last checked
	// (Wallet.CheckStatus). Each is absent when unknown.
	Display    *displayJSON `json:"display,omitempty"`
	ValidUntil *time.Time   `json:"valid_until,omitempty"`
	Status     *statusJSON  `json:"status,omitempty"`
	// Copies is how many copies the wallet holds, each bound to its own
	// key; CopiesLeft how many no Verifier has seen. A presentation uses
	// one of those, so presentations can't be linked by the credential,
	// until none is left.
	Copies     int `json:"copies"`
	CopiesLeft int `json:"copies_left"`
	// Refreshable is whether its issuance kept a refresh token
	// ("request_refresh"), so Wallet.RefreshCredential can replace its
	// copies without the holder. The Authorization Server may still
	// refuse it (reissue_required).
	Refreshable bool `json:"refreshable"`
	// Linkable is whether a copy has been presented to more than one
	// Verifier, so those Verifiers could link the holder's presentations
	// (walletflow.StoredCredential.Linkable). Refreshing gives it copies
	// no Verifier has seen.
	Linkable bool `json:"linkable"`
	// ShownToVerifier and LinkableHere, set only for a presentation's
	// candidates (Presentation.Queries): whether the Verifier asking has
	// been shown this credential before, and whether presenting it now
	// would hand it a copy another Verifier has seen.
	ShownToVerifier *bool `json:"shown_to_verifier,omitempty"`
	LinkableHere    *bool `json:"linkable_here,omitempty"`
	// HolderKeyPresent is whether the key store still holds the
	// credential's key; without it the credential can't be presented
	// (restored from a backup to another device, say). Set only by
	// Wallet.Credentials and Wallet.Credential.
	HolderKeyPresent *bool `json:"holder_key_present,omitempty"`
}

func summaryOf(c walletflow.StoredCredential) credentialSummary {
	s := credentialSummary{
		ID: c.ID, CredentialIssuer: c.CredentialIssuer, ConfigurationID: c.ConfigurationID, Format: c.Format,
		VCT: c.VCT, DocType: c.DocType, ReceivedAt: c.ReceivedAt, Display: displayOf(c.Display),
		Copies: len(c.AllCopies()), CopiesLeft: c.CopiesLeft(), Refreshable: c.GrantID != "", Linkable: c.Linkable(),
	}
	if !c.ValidUntil.IsZero() {
		s.ValidUntil = &c.ValidUntil
	}
	if c.Status.Value != "" {
		s.Status = &statusJSON{Value: c.Status.Value, CheckedAt: c.Status.CheckedAt}
	}
	return s
}

func summariesOf(cs []walletflow.StoredCredential) []credentialSummary {
	out := make([]credentialSummary, 0, len(cs))
	for _, c := range cs {
		out = append(out, summaryOf(c))
	}
	return out
}

// credentialStore is a CredentialStore as a walletflow.CredentialStore.
type credentialStore struct{ cs CredentialStore }

var _ walletflow.CredentialStore = credentialStore{}

func (s credentialStore) Put(_ context.Context, c walletflow.StoredCredential) error {
	r, err := recordOf(c)
	if err != nil {
		return newError(CodeInternal, err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return newError(CodeInternal, err)
	}
	if err := s.cs.Put(c.ID, raw); err != nil {
		return newError(CodePlatform, fmt.Errorf("store credential: %w", err))
	}
	return nil
}

func (s credentialStore) Get(_ context.Context, id string) (walletflow.StoredCredential, error) {
	raw, err := s.cs.Get(id)
	if err != nil {
		return walletflow.StoredCredential{}, newError(CodePlatform, fmt.Errorf("credential %q: %w", id, err))
	}
	if len(raw) == 0 {
		return walletflow.StoredCredential{}, fmt.Errorf("mobile: credential %q: %w", id, walletflow.ErrNotFound)
	}
	if kindOf(raw) != "" {
		return walletflow.StoredCredential{}, fmt.Errorf("mobile: credential %q: %w", id, walletflow.ErrNotFound)
	}
	var r credentialRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return walletflow.StoredCredential{}, newError(CodePlatform, fmt.Errorf("credential %q's record: %w", id, err))
	}
	if r.ID != id {
		// A record for another credential: its holder key isn't this one's.
		return walletflow.StoredCredential{}, newError(CodePlatform, fmt.Errorf("the record stored as %q is for credential %q", id, r.ID))
	}
	c, err := r.stored()
	if err != nil {
		return walletflow.StoredCredential{}, newError(CodePlatform, fmt.Errorf("credential %q's record: %w", id, err))
	}
	return c, nil
}

func (s credentialStore) List(context.Context) ([]walletflow.StoredCredential, error) {
	all, err := listRecords(s.cs)
	if err != nil {
		return nil, err
	}
	var records []credentialRecord
	for _, raw := range all {
		if kindOf(raw) != "" { // a deferred credential or an authorization
			continue
		}
		var r credentialRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, newError(CodePlatform, fmt.Errorf("credential records: %w", err))
		}
		records = append(records, r)
	}
	out := make([]walletflow.StoredCredential, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, r := range records {
		if r.ID == "" || seen[r.ID] {
			return nil, newError(CodePlatform, fmt.Errorf("the credential store lists credential %q twice, or one without an ID", r.ID))
		}
		seen[r.ID] = true
		c, err := r.stored()
		if err != nil {
			return nil, newError(CodePlatform, fmt.Errorf("credential %q's record: %w", r.ID, err))
		}
		out = append(out, c)
	}
	return out, nil
}

func (s credentialStore) Delete(_ context.Context, id string) error {
	if err := s.cs.Delete(id); err != nil {
		return newError(CodePlatform, fmt.Errorf("delete credential %q: %w", id, err))
	}
	return nil
}

// listRecords returns every record in cs.
func listRecords(cs CredentialStore) ([]json.RawMessage, error) {
	raw, err := cs.List()
	if err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("list credentials: %w", err))
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var all []json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("credential records: %w", err))
	}
	return all, nil
}

// deferredKind marks a record that's a pending deferred credential, not
// a credential: both are kept in the app's CredentialStore, under its
// data protection.
const deferredKind = "deferred"

// kindOf is a record's "kind": "" for a credential.
func kindOf(raw json.RawMessage) string {
	var k struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal(raw, &k)
	return k.Kind
}

// deferredRecord is a pending deferred credential as the CredentialStore
// keeps it, under the ID deferredStoreID gives it.
type deferredRecord struct {
	Kind                 string     `json:"kind"`
	ID                   string     `json:"id"`
	CredentialIssuer     string     `json:"credential_issuer"`
	ConfigurationID      string     `json:"configuration_id"`
	TransactionID        string     `json:"transaction_id"`
	AccessToken          string     `json:"access_token"`
	AccessTokenExpiresAt *time.Time `json:"access_token_expires_at,omitempty"`
	DPoPKeyID            string     `json:"dpop_key_id"`
	HolderKeyIDs         []string   `json:"holder_key_ids"`
	// HolderKeyID is a record's one holder key from before batches.
	HolderKeyID     string    `json:"holder_key_id,omitempty"`
	IntervalSeconds float64   `json:"interval_seconds"`
	DeferredAt      time.Time `json:"deferred_at"`
	GrantID         string    `json:"grant_id,omitempty"`
	Replaces        string    `json:"replaces,omitempty"`
}

// deferredStoreID is the CredentialStore ID a pending deferred
// credential is kept under.
func deferredStoreID(id string) string { return "deferred-" + id }

// deferredStore is a CredentialStore as a walletflow.DeferredStore.
type deferredStore struct{ cs CredentialStore }

var _ walletflow.DeferredStore = deferredStore{}

func (s deferredStore) PutDeferred(_ context.Context, p walletflow.PendingDeferred) error {
	r := deferredRecord{
		Kind: deferredKind, ID: p.ID, CredentialIssuer: p.CredentialIssuer, ConfigurationID: p.ConfigurationID,
		TransactionID: p.TransactionID, AccessToken: p.AccessToken.Reveal(),
		DPoPKeyID: p.DPoPKeyID, HolderKeyIDs: p.HolderKeyIDs, IntervalSeconds: p.Interval.Seconds(), DeferredAt: p.DeferredAt,
		GrantID: p.GrantID, Replaces: p.Replaces,
	}
	if !p.AccessTokenExpiresAt.IsZero() {
		r.AccessTokenExpiresAt = &p.AccessTokenExpiresAt
	}
	// The access token is kept deliberately, to poll after a relaunch:
	// it's bound to a DPoP key that never leaves the KeyStore, and the
	// record is under the platform's data protection.
	raw, err := json.Marshal(r) //nolint:gosec // G117: see above
	if err != nil {
		return newError(CodeInternal, err)
	}
	if err := s.cs.Put(deferredStoreID(p.ID), raw); err != nil {
		return newError(CodePlatform, fmt.Errorf("store deferred credential: %w", err))
	}
	return nil
}

func (s deferredStore) ListDeferred(context.Context) ([]walletflow.PendingDeferred, error) {
	all, err := listRecords(s.cs)
	if err != nil {
		return nil, err
	}
	var out []walletflow.PendingDeferred
	for _, raw := range all {
		if kindOf(raw) != deferredKind {
			continue
		}
		var r deferredRecord
		if err := json.Unmarshal(raw, &r); err != nil || r.ID == "" {
			return nil, newError(CodePlatform, errors.New("a deferred credential's record is malformed"))
		}
		p := walletflow.PendingDeferred{
			ID: r.ID, CredentialIssuer: r.CredentialIssuer, ConfigurationID: r.ConfigurationID, TransactionID: r.TransactionID,
			AccessToken: fapi.NewSecret(r.AccessToken), DPoPKeyID: r.DPoPKeyID, HolderKeyIDs: r.HolderKeyIDs,
			Interval: time.Duration(r.IntervalSeconds * float64(time.Second)), DeferredAt: r.DeferredAt,
			GrantID: r.GrantID, Replaces: r.Replaces,
		}
		if r.AccessTokenExpiresAt != nil {
			p.AccessTokenExpiresAt = *r.AccessTokenExpiresAt
		}
		if len(p.HolderKeyIDs) == 0 && r.HolderKeyID != "" {
			p.HolderKeyIDs = []string{r.HolderKeyID}
		}
		out = append(out, p)
	}
	return out, nil
}

func (s deferredStore) DeleteDeferred(_ context.Context, id string) error {
	if err := s.cs.Delete(deferredStoreID(id)); err != nil {
		return newError(CodePlatform, fmt.Errorf("delete deferred credential: %w", err))
	}
	return nil
}

// authorizationKind marks a record that's an authorization in progress.
const authorizationKind = "authorization"

// authorizationRecord is an authorization in progress as the
// CredentialStore keeps it, under the ID authorizationStoreID gives it.
type authorizationRecord struct {
	Kind                string                  `json:"kind"`
	State               string                  `json:"state"`
	Session             json.RawMessage         `json:"session"`
	ExpiresAt           time.Time               `json:"expires_at"`
	Offer               oid4vci.CredentialOffer `json:"offer"`
	AuthorizationServer string                  `json:"authorization_server"`
	InstanceKeyID       string                  `json:"instance_key_id"`
	DPoPKeyID           string                  `json:"dpop_key_id"`
	CreatedAt           time.Time               `json:"created_at"`
}

// authorizationStoreID is the CredentialStore ID an authorization is
// kept under: a hash of its state, which isn't put in an ID.
func authorizationStoreID(state string) string {
	sum := sha256.Sum256([]byte(state))
	return "authorization-" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// authorizationStore is a CredentialStore as a
// walletflow.AuthorizationStore.
type authorizationStore struct{ cs CredentialStore }

var _ walletflow.AuthorizationStore = authorizationStore{}

func (s authorizationStore) PutAuthorization(_ context.Context, a walletflow.PendingAuthorization) error {
	// The session record holds the PKCE verifier: kept deliberately, to
	// complete the authorization after a relaunch. It's no use without
	// the DPoP and instance keys, which never leave the KeyStore.
	raw, err := json.Marshal(authorizationRecord{ //nolint:gosec // G117: see above
		Kind: authorizationKind, State: a.State, Session: a.Session, ExpiresAt: a.ExpiresAt, Offer: a.Offer,
		AuthorizationServer: a.AuthorizationServer, InstanceKeyID: a.InstanceKeyID, DPoPKeyID: a.DPoPKeyID, CreatedAt: a.CreatedAt,
	})
	if err != nil {
		return newError(CodeInternal, err)
	}
	if err := s.cs.Put(authorizationStoreID(a.State), raw); err != nil {
		return newError(CodePlatform, fmt.Errorf("store authorization: %w", err))
	}
	return nil
}

func (s authorizationStore) GetAuthorization(_ context.Context, state string) (walletflow.PendingAuthorization, error) {
	raw, err := s.cs.Get(authorizationStoreID(state))
	if err != nil {
		return walletflow.PendingAuthorization{}, newError(CodePlatform, fmt.Errorf("authorization: %w", err))
	}
	if len(raw) == 0 {
		return walletflow.PendingAuthorization{}, fmt.Errorf("mobile: authorization: %w", walletflow.ErrNotFound)
	}
	a, err := pendingAuthorization(raw)
	if err != nil || a.State != state {
		return walletflow.PendingAuthorization{}, newError(CodePlatform, errors.New("an authorization's record is malformed"))
	}
	return a, nil
}

func (s authorizationStore) ListAuthorizations(context.Context) ([]walletflow.PendingAuthorization, error) {
	all, err := listRecords(s.cs)
	if err != nil {
		return nil, err
	}
	var out []walletflow.PendingAuthorization
	for _, raw := range all {
		if kindOf(raw) != authorizationKind {
			continue
		}
		a, err := pendingAuthorization(raw)
		if err != nil {
			return nil, newError(CodePlatform, errors.New("an authorization's record is malformed"))
		}
		out = append(out, a)
	}
	return out, nil
}

func (s authorizationStore) DeleteAuthorization(_ context.Context, state string) error {
	if err := s.cs.Delete(authorizationStoreID(state)); err != nil {
		return newError(CodePlatform, fmt.Errorf("delete authorization: %w", err))
	}
	return nil
}

func (s authorizationStore) Durable() bool { return s.cs.Durable() }

func pendingAuthorization(raw []byte) (walletflow.PendingAuthorization, error) {
	var r authorizationRecord
	if err := json.Unmarshal(raw, &r); err != nil || r.State == "" {
		return walletflow.PendingAuthorization{}, errors.New("malformed")
	}
	return walletflow.PendingAuthorization{
		State: r.State, Session: r.Session, ExpiresAt: r.ExpiresAt, Offer: r.Offer, AuthorizationServer: r.AuthorizationServer,
		InstanceKeyID: r.InstanceKeyID, DPoPKeyID: r.DPoPKeyID, CreatedAt: r.CreatedAt,
	}, nil
}

// walletProvider is a WalletProvider as a walletflow.WalletProvider.
type walletProvider struct{ p WalletProvider }

var _ walletflow.WalletProvider = walletProvider{}

func (w walletProvider) WalletAttestation(ctx context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	jwk, err := attestation.AttestedKey(instanceKey)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	jwt, err := cancellable(ctx, func() ([]byte, error) { return w.p.WalletAttestation(clientID, jwk) })
	if err != nil {
		return "", providerError("wallet attestation", err)
	}
	if len(jwt) == 0 {
		return "", newError(CodePlatform, errors.New("wallet attestation: none returned"))
	}
	return string(jwt), nil
}

func (w walletProvider) KeyAttestation(ctx context.Context, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	jwks := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		jwk, err := attestation.AttestedKey(k)
		if err != nil {
			return "", newError(CodeInternal, err)
		}
		jwks = append(jwks, jwk)
	}
	raw, err := json.Marshal(jwks)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	jwt, err := cancellable(ctx, func() ([]byte, error) { return w.p.KeyAttestation(raw, nonce) })
	if err != nil {
		return "", providerError("key attestation", err)
	}
	if len(jwt) == 0 {
		return "", newError(CodePlatform, errors.New("key attestation: none returned"))
	}
	return string(jwt), nil
}

// cancellable runs a Wallet Provider callback, which may wait on the
// network, and returns early when ctx is done: the callback carries on,
// and its result is dropped.
func cancellable(ctx context.Context, call func() ([]byte, error)) ([]byte, error) {
	type answer struct {
		jwt []byte
		err error
	}
	done := make(chan answer, 1)
	go func() {
		jwt, err := call()
		done <- answer{jwt, err}
	}()
	select {
	case a := <-done:
		return a.jwt, a.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// networkPrefix starts the message of a Wallet Provider callback's error
// for a network failure, so it's classified as one: the Swift package's
// adapter marks a URLError so.
const networkPrefix = "[network]"

// providerError is a Wallet Provider callback's err doing what: a
// cancellation as is, a network failure the callback marked as network,
// anything else as platform.
func providerError(what string, err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case strings.HasPrefix(err.Error(), networkPrefix):
		return newError(CodeNetwork, fmt.Errorf("%s: %s", what, strings.TrimSpace(strings.TrimPrefix(err.Error(), networkPrefix))))
	}
	return newError(CodePlatform, fmt.Errorf("%s: %w", what, err))
}

// jsonClaims makes claims JSON-safe: an mdoc's element values are
// decoded CBOR, so byte strings become standard base64, a tagged value
// (an mdoc's tdate or full-date) its content, and a map with
// non-string keys one with their text.
func jsonClaims(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[k] = jsonClaims(e)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			out[fmt.Sprint(k)] = jsonClaims(e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = jsonClaims(e)
		}
		return out
	case []byte:
		return base64.StdEncoding.EncodeToString(v)
	case cbor.Tag:
		return jsonClaims(v.Content)
	case time.Time:
		return v.UTC().Format(time.RFC3339)
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return strconv.FormatFloat(v, 'g', -1, 64) // JSON has no NaN or Inf
		}
		return v
	case float32:
		return jsonClaims(float64(v))
	default:
		return v
	}
}
