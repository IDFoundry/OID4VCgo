// Package interopwp is the wallet's side of OID4VCgo's Wallet Provider
// protocol (walletprovider.Handler) for the interop runs: a
// walletflow.WalletProvider that obtains every Wallet Attestation and
// Key Attestation from a running walletprovider.Provider over HTTPS,
// with walletprovider.Client, as the Swift and Kotlin libraries'
// HttpWalletProvider does on a device.
//
// The one stand-in is the platform evidence. A run has no device, so
// each piece of evidence is walletprovidertest.FakeEvidence, which the
// provider under test accepts with walletprovidertest.FakeVerifier:
// registration, each new instance key and each Key Attestation still
// need a challenge the provider issued and evidence bound to it, and
// every request after registration is signed with the instance's
// registration key. Everything else — the stores, status lists,
// policy and the attestations themselves — is the provider's own.
package interopwp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

// EvidenceKind is the evidence kind the interop Wallet Provider's
// FakeVerifier reads.
const EvidenceKind = walletprovidertest.FakeKind

// Provider is one registered wallet instance, asking the provider at
// its base URL for attestations. It implements walletflow.WalletProvider
// and is safe for concurrent use.
type Provider struct {
	client          *walletprovider.Client
	registrationKey *ecdsa.PrivateKey

	mu         sync.Mutex
	instanceID string
}

var _ walletflow.WalletProvider = (*Provider)(nil)

// Register registers a new wallet instance with the provider at
// baseURL, its Handler's https URL, over hc (which trusts the
// provider's TLS certificate), and returns it.
func Register(ctx context.Context, baseURL string, hc *http.Client) (*Provider, error) {
	client, err := walletprovider.NewClient(baseURL, walletprovider.ClientOptions{HTTP: hc})
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	p := &Provider{client: client, registrationKey: key}
	ch, err := client.Challenge(ctx, walletprovider.PurposeRegistration)
	if err != nil {
		return nil, fmt.Errorf("interopwp: registration challenge: %w", err)
	}
	ev, err := walletprovidertest.FakeEvidence(EvidenceKind, ch.Value, key.Public())
	if err != nil {
		return nil, err
	}
	id, err := client.Register(ctx, walletprovider.RegisterRequest{Challenge: ch.Value, RegistrationKey: key.Public(), Evidence: ev})
	if err != nil {
		return nil, fmt.Errorf("interopwp: register: %w", err)
	}
	p.instanceID = id
	return p, nil
}

// InstanceID is the instance's ID at the provider.
func (p *Provider) InstanceID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.instanceID
}

// WalletAttestation implements walletflow.WalletProvider: a Wallet
// Attestation for clientID binding instanceKey, with evidence for the
// key over a fresh PurposeInstance challenge, which the provider needs
// the first time it sees the key and ignores afterwards.
func (p *Provider) WalletAttestation(ctx context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	ch, err := p.client.Challenge(ctx, walletprovider.PurposeInstance)
	if err != nil {
		return "", fmt.Errorf("interopwp: instance key challenge: %w", err)
	}
	ev, err := walletprovidertest.FakeEvidence(EvidenceKind, ch.Value, instanceKey)
	if err != nil {
		return "", err
	}
	return p.client.WalletAttestation(ctx, p.registrationKey, walletprovider.WalletAttestationRequest{
		InstanceID: p.InstanceID(), ClientID: clientID, InstanceKey: instanceKey, Challenge: ch.Value, Evidence: ev,
	})
}

// KeyAttestation implements walletflow.WalletProvider: a Key
// Attestation over keys carrying nonce, for the issuance whose instance
// key is instanceKey, with one piece of evidence for all the keys over a
// fresh PurposeHolder challenge. It fails unless the provider attested
// every key asked for.
func (p *Provider) KeyAttestation(ctx context.Context, instanceKey crypto.PublicKey, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("interopwp: no keys to attest")
	}
	pubs := make([]crypto.PublicKey, len(keys))
	for i, k := range keys {
		pubs[i] = k
	}
	ch, err := p.client.Challenge(ctx, walletprovider.PurposeHolder)
	if err != nil {
		return "", fmt.Errorf("interopwp: holder key challenge: %w", err)
	}
	ev, err := walletprovidertest.FakeEvidence(EvidenceKind, ch.Value, pubs...)
	if err != nil {
		return "", err
	}
	res, err := p.client.KeyAttestation(ctx, p.registrationKey, walletprovider.KeyAttestationRequest{
		InstanceID: p.InstanceID(), InstanceKey: instanceKey, Challenge: ch.Value, Keys: pubs, Nonce: nonce,
		Evidence: []walletprovider.Evidence{ev},
	})
	if err != nil {
		return "", err
	}
	if len(res.AttestedKeys) != len(keys) {
		return "", fmt.Errorf("interopwp: the provider attested %d of the %d keys", len(res.AttestedKeys), len(keys))
	}
	return res.JWT, nil
}
