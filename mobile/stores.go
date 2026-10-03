package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/attestation"
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
}

func recordOf(c walletflow.StoredCredential) (credentialRecord, error) {
	r := credentialRecord{
		ID: c.ID, CredentialIssuer: c.CredentialIssuer, ConfigurationID: c.ConfigurationID, Format: c.Format,
		VCT: c.VCT, DocType: c.DocType, Credential: c.Credential, HolderKeyID: c.HolderKeyID, ReceivedAt: c.ReceivedAt,
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
	// HolderKeyPresent is whether the key store still holds the
	// credential's key; without it the credential can't be presented
	// (restored from a backup to another device, say). Set only by
	// Wallet.Credentials and Wallet.Credential.
	HolderKeyPresent *bool `json:"holder_key_present,omitempty"`
}

func summaryOf(c walletflow.StoredCredential) credentialSummary {
	return credentialSummary{
		ID: c.ID, CredentialIssuer: c.CredentialIssuer, ConfigurationID: c.ConfigurationID, Format: c.Format,
		VCT: c.VCT, DocType: c.DocType, ReceivedAt: c.ReceivedAt,
	}
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
	raw, err := s.cs.List()
	if err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("list credentials: %w", err))
	}
	if len(raw) == 0 {
		return nil, nil
	}
	var records []credentialRecord
	if err := json.Unmarshal(raw, &records); err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("credential records: %w", err))
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

// walletProvider is a WalletProvider as a walletflow.WalletProvider.
type walletProvider struct{ p WalletProvider }

var _ walletflow.WalletProvider = walletProvider{}

func (w walletProvider) WalletAttestation(_ context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	jwk, err := attestation.AttestedKey(instanceKey)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	jwt, err := w.p.WalletAttestation(clientID, jwk)
	if err != nil {
		return "", newError(CodePlatform, fmt.Errorf("wallet attestation: %w", err))
	}
	if len(jwt) == 0 {
		return "", newError(CodePlatform, errors.New("wallet attestation: none returned"))
	}
	return string(jwt), nil
}

func (w walletProvider) KeyAttestation(_ context.Context, keys []*ecdsa.PublicKey, nonce string) (string, error) {
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
	jwt, err := w.p.KeyAttestation(raw, nonce)
	if err != nil {
		return "", newError(CodePlatform, fmt.Errorf("key attestation: %w", err))
	}
	if len(jwt) == 0 {
		return "", newError(CodePlatform, errors.New("key attestation: none returned"))
	}
	return string(jwt), nil
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
