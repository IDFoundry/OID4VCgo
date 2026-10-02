package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"time"

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
}

func recordOf(c walletflow.StoredCredential) credentialRecord {
	return credentialRecord{
		ID: c.ID, CredentialIssuer: c.CredentialIssuer, ConfigurationID: c.ConfigurationID, Format: c.Format,
		VCT: c.VCT, DocType: c.DocType, Credential: c.Credential, HolderKeyID: c.HolderKeyID, ReceivedAt: c.ReceivedAt,
	}
}

func (r credentialRecord) stored() walletflow.StoredCredential {
	return walletflow.StoredCredential{
		ID: r.ID, CredentialIssuer: r.CredentialIssuer, ConfigurationID: r.ConfigurationID, Format: r.Format,
		VCT: r.VCT, DocType: r.DocType, Credential: r.Credential, HolderKeyID: r.HolderKeyID, ReceivedAt: r.ReceivedAt,
	}
}

// credentialSummary is a credential as the app shows it: everything but
// the credential itself and its key.
type credentialSummary struct {
	ID               string    `json:"id"`
	CredentialIssuer string    `json:"credential_issuer"`
	ConfigurationID  string    `json:"configuration_id"`
	Format           string    `json:"format"`
	VCT              string    `json:"vct,omitempty"`
	DocType          string    `json:"doctype,omitempty"`
	ReceivedAt       time.Time `json:"received_at"`
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
	raw, err := json.Marshal(recordOf(c))
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
	return r.stored(), nil
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
	for _, r := range records {
		out = append(out, r.stored())
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
