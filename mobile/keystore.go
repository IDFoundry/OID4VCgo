package mobile

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Key purposes, as KeyStore.CreateKey receives them (walletflow.KeyPurpose).
const (
	// PurposeInstance: the wallet instance key a Wallet Attestation binds.
	PurposeInstance = string(walletflow.KeyPurposeInstance)
	// PurposeDPoP: the key access tokens are bound to.
	PurposeDPoP = string(walletflow.KeyPurposeDPoP)
	// PurposeHolder: the key a credential is bound to, used only when
	// presenting it — the one to protect with user presence.
	PurposeHolder = string(walletflow.KeyPurposeHolder)
)

// KeyStore holds the wallet's P-256 keys for it — in the Secure Enclave
// or Android Keystore — so private keys never cross the boundary: Go
// asks it to create a key, for a key's public half, and to sign a
// digest.
type KeyStore interface {
	// CreateKey creates a P-256 key for purpose (PurposeInstance,
	// PurposeDPoP or PurposeHolder) and returns its ID. (Not NewKey:
	// Objective-C reserves methods named new… for returning an owned
	// object.) An error whose message starts with "[network]" — a store
	// that fetched a key attestation challenge from the Wallet Provider
	// first, say — is reported as CodeNetwork (retryable); any other as
	// CodePlatform.
	CreateKey(purpose string) (string, error)
	// PublicKey returns key id's public key as an uncompressed X9.63
	// point (0x04 || X || Y) — empty, with no error, when there's no
	// such key.
	PublicKey(id string) ([]byte, error)
	// Sign signs a SHA-256 digest with key id, returning an ASN.1 DER
	// ECDSA signature. It may ask the user (Face ID) for a holder key.
	Sign(id string, digest []byte) ([]byte, error)
	// DeleteKey deletes key id. Deleting a key that doesn't exist isn't
	// an error.
	DeleteKey(id string) error
	// Durable reports whether keys survive the app quitting (kept in the
	// Keychain). Receiving credentials needs a durable KeyStore unless
	// the wallet is configured for development.
	Durable() bool
}

// KeyAgreement agrees keys with the wallet's holder keys — ECDH inside
// the platform key store — so an in-person response can authenticate
// with deviceMac (ISO/IEC 18013-5 §9.1.3.5) rather than a signature. An
// app gives one with Wallet.SetKeyAgreement; without one, the wallet
// signs.
type KeyAgreement interface {
	// Agree runs ECDH between key id and peerPublicKey, an uncompressed
	// X9.63 P-256 point, and returns the shared secret: its 32-byte
	// x-coordinate. For a key that can't agree keys (created for
	// signing only), it fails with a message starting with
	// "[no_key_agreement]": the wallet then signs instead.
	Agree(id string, peerPublicKey []byte) ([]byte, error)
}

// noKeyAgreementPrefix starts the message of a KeyAgreement's error for
// a key that can't agree keys.
const noKeyAgreementPrefix = "[no_key_agreement]"

// agreement holds a Wallet's KeyAgreement, which SetKeyAgreement may set
// after its keys are made.
type agreement struct{ ka atomic.Pointer[KeyAgreement] }

func (a *agreement) get() KeyAgreement {
	if a == nil {
		return nil
	}
	if p := a.ka.Load(); p != nil {
		return *p
	}
	return nil
}

// keyStore is a KeyStore as a walletflow.KeyStore.
type keyStore struct {
	ks KeyStore
	ka *agreement
}

// KeyCustody declares the KeyStore's custody to fapigo/client: its keys
// are durable when it says so.
func (k keyStore) KeyCustody() keys.KeyCustody { return keys.KeyCustody{Durable: k.ks.Durable()} }

var _ walletflow.KeyStore = keyStore{}

func (k keyStore) NewKey(_ context.Context, purpose walletflow.KeyPurpose) (walletflow.Key, error) {
	id, err := k.ks.CreateKey(string(purpose))
	if err != nil {
		// A store that asks the Wallet Provider for a key attestation
		// challenge first (the Kotlin library's) marks its network
		// failure as a provider's is marked: retryable.
		return nil, providerError("new "+string(purpose)+" key", err)
	}
	if id == "" {
		return nil, newError(CodePlatform, fmt.Errorf("new %s key: no key ID", purpose))
	}
	key, err := k.load(id)
	if err != nil {
		// Don't leave behind a key the wallet can't use.
		_ = k.ks.DeleteKey(id)
		if errors.Is(err, walletflow.ErrNotFound) {
			return nil, newError(CodePlatform, fmt.Errorf("new %s key %q isn't in the key store", purpose, id))
		}
		return nil, err
	}
	return key, nil
}

func (k keyStore) Key(_ context.Context, id string) (walletflow.Key, error) { return k.load(id) }

func (k keyStore) DeleteKey(_ context.Context, id string) error {
	if err := k.ks.DeleteKey(id); err != nil {
		return newError(CodePlatform, fmt.Errorf("delete key %q: %w", id, err))
	}
	return nil
}

// load returns key id, or an error wrapping walletflow.ErrNotFound.
func (k keyStore) load(id string) (*platformKey, error) {
	raw, err := k.ks.PublicKey(id)
	if err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("key %q: %w", id, err))
	}
	if len(raw) == 0 {
		return nil, &notFoundError{id}
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("key %q's public key: %w", id, err))
	}
	return &platformKey{ks: k.ks, ka: k.ka, id: id, pub: pub}, nil
}

// notFoundError is a missing key: a CodeNotFound Error that is also
// walletflow.ErrNotFound.
type notFoundError struct{ id string }

func (e *notFoundError) Error() string {
	return (&Error{Code: CodeNotFound, Message: fmt.Sprintf("no key %q", e.id)}).Error()
}

func (e *notFoundError) Is(target error) bool { return target == walletflow.ErrNotFound }

func (e *notFoundError) As(target any) bool {
	if t, ok := target.(**Error); ok {
		*t = &Error{Code: CodeNotFound, Message: fmt.Sprintf("no key %q", e.id)}
		return true
	}
	return false
}

// platformKey is a key in the app's KeyStore, as a walletflow.Key: a
// crypto.Signer whose private half stays in the KeyStore.
type platformKey struct {
	ks  KeyStore
	ka  *agreement
	id  string
	pub *ecdsa.PublicKey
}

var _ proximity.KeyAgreer = (*platformKey)(nil)

// Agree implements proximity.KeyAgreer through the Wallet's
// KeyAgreement: without one, or for a key that can't agree keys, an
// error wrapping proximity.ErrNoKeyAgreement, so the response is signed.
func (p *platformKey) Agree(peer *ecdsa.PublicKey) ([]byte, error) {
	ka := p.ka.get()
	if ka == nil {
		return nil, proximity.ErrNoKeyAgreement
	}
	raw, err := peer.Bytes()
	if err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("peer key: %w", err))
	}
	z, err := ka.Agree(p.id, raw)
	switch {
	case err != nil && strings.HasPrefix(err.Error(), noKeyAgreementPrefix):
		return nil, fmt.Errorf("key %q: %w", p.id, proximity.ErrNoKeyAgreement)
	case err != nil:
		return nil, newError(CodePlatform, fmt.Errorf("agree with key %q: %w", p.id, err))
	case len(z) != 32:
		return nil, newError(CodePlatform, fmt.Errorf("key %q agreed a %d-byte secret, want 32", p.id, len(z)))
	}
	return z, nil
}

func (p *platformKey) ID() string { return p.id }

func (p *platformKey) Public() crypto.PublicKey { return p.pub }

// Sign asks the KeyStore to sign digest, and checks the signature under
// the key's public key, so a store signing with the wrong key fails
// here rather than at an issuer or verifier.
func (p *platformKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, fmt.Errorf("mobile: platform keys sign SHA-256 digests only")
	}
	sig, err := p.ks.Sign(p.id, digest)
	if err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("sign with key %q: %w", p.id, err))
	}
	if !ecdsa.VerifyASN1(p.pub, digest, sig) {
		return nil, newError(CodePlatform, fmt.Errorf("key %q's signature doesn't verify under its public key", p.id))
	}
	return sig, nil
}

// CheckKeyStore exercises store as the wallet will: for each purpose it
// creates a key, signs a DPoP proof with it (wallet.GenerateDPoPProof)
// and a FAPIgo signing request (keys.NewKeyManagerFromSigners, as
// walletflow's OAuth client does), checking both signatures, looks the
// key up again, deletes it, and checks it's gone. It returns
// {"abi", "checked": [purposes]} or the first failure. A store that asks
// for user presence on holder keys prompts once here.
func CheckKeyStore(store KeyStore) (string, error) {
	if store == nil {
		return "", newError(CodeInvalidInput, errors.New("no key store"))
	}
	ctx := context.Background()
	ks := keyStore{ks: store}
	w, err := newCoreWallet()
	if err != nil {
		return "", err
	}
	var checked []string
	for _, purpose := range []walletflow.KeyPurpose{walletflow.KeyPurposeInstance, walletflow.KeyPurposeDPoP, walletflow.KeyPurposeHolder} {
		if err := checkPurpose(ctx, ks, w, purpose); err != nil {
			return "", err
		}
		checked = append(checked, string(purpose))
	}
	out, err := json.Marshal(struct {
		result
		Checked []string `json:"checked"`
	}{result{ABIVersion}, checked})
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	return string(out), nil
}

func checkPurpose(ctx context.Context, ks keyStore, w *wallet.Wallet, purpose walletflow.KeyPurpose) error {
	key, err := ks.NewKey(ctx, purpose)
	if err != nil {
		return err
	}
	pub := key.Public().(*ecdsa.PublicKey)
	proof, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example/token", "", "")
	if err != nil {
		_ = ks.DeleteKey(ctx, key.ID())
		return asError(CodeInternal, fmt.Errorf("%s key: DPoP proof: %w", purpose, err))
	}
	if err := verifyES256(proof, pub); err != nil {
		_ = ks.DeleteKey(ctx, key.ID())
		return newError(CodePlatform, fmt.Errorf("%s key: %w", purpose, err))
	}
	km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{{Purpose: keys.DPoPProofSigning, Algorithm: fapi.ES256, Signer: key}})
	if err != nil {
		_ = ks.DeleteKey(ctx, key.ID())
		return newError(CodeInternal, fmt.Errorf("%s key: key manager: %w", purpose, err))
	}
	digest := sha256.Sum256([]byte("oid4vcgo key store check"))
	sig, err := km.Sign(ctx, keys.NewSigningRequest(keys.DPoPProofSigning, fapi.ES256, digest[:]))
	if err != nil {
		_ = ks.DeleteKey(ctx, key.ID())
		return asError(CodePlatform, fmt.Errorf("%s key: FAPIgo signing request: %w", purpose, err))
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig.Value) {
		_ = ks.DeleteKey(ctx, key.ID())
		return newError(CodePlatform, fmt.Errorf("%s key: FAPIgo signature doesn't verify", purpose))
	}
	again, err := ks.Key(ctx, key.ID())
	if err != nil {
		_ = ks.DeleteKey(ctx, key.ID())
		return asError(CodePlatform, fmt.Errorf("%s key: look up again: %w", purpose, err))
	}
	if !again.Public().(*ecdsa.PublicKey).Equal(pub) {
		_ = ks.DeleteKey(ctx, key.ID())
		return newError(CodePlatform, fmt.Errorf("%s key: looked up again, it has another public key", purpose))
	}
	if err := ks.DeleteKey(ctx, key.ID()); err != nil {
		return err
	}
	if _, err := ks.Key(ctx, key.ID()); !errors.Is(err, walletflow.ErrNotFound) {
		return newError(CodePlatform, fmt.Errorf("%s key: still there after DeleteKey (%v)", purpose, err))
	}
	return nil
}

// CheckKeyAgreement exercises ka with store's holder keys as deviceMac
// will: it creates a holder key, agrees a key with a fresh P-256 key,
// checks the secret is the one the other side computes, and deletes the
// key. It returns {"abi", "key_agreement"}: "supported", or
// "unsupported" when ka reports the holder key can't agree keys (the
// wallet then signs), or the first failure.
func CheckKeyAgreement(store KeyStore, ka KeyAgreement) (string, error) {
	if store == nil || ka == nil {
		return "", newError(CodeInvalidInput, errors.New("a key store and a key agreement are required"))
	}
	ctx := context.Background()
	ks := keyStore{ks: store, ka: &agreement{}}
	ks.ka.ka.Store(&ka)
	key, err := ks.NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		return "", err
	}
	defer func() { _ = ks.DeleteKey(ctx, key.ID()) }()
	status, err := checkAgreement(key)
	if err != nil {
		return "", err
	}
	return marshal(struct {
		result
		KeyAgreement string `json:"key_agreement"`
	}{result{ABIVersion}, status})
}

func checkAgreement(key walletflow.Key) (string, error) {
	peer, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	peerPub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), peer.PublicKey().Bytes())
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	z, err := key.(proximity.KeyAgreer).Agree(peerPub)
	if errors.Is(err, proximity.ErrNoKeyAgreement) {
		return "unsupported", nil
	}
	if err != nil {
		return "", asError(CodePlatform, err)
	}
	holderPub, err := key.Public().(*ecdsa.PublicKey).ECDH()
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	want, err := peer.ECDH(holderPub)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	if subtle.ConstantTimeCompare(z, want) != 1 {
		return "", newError(CodePlatform, errors.New("holder key: the agreed secret isn't the peer's"))
	}
	return "supported", nil
}

// newCoreWallet returns the wallet package's Wallet, for the protocol
// messages the spike builds.
func newCoreWallet() (*wallet.Wallet, error) {
	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: "ES256",
		Fetch: fapihttp.Config{MaxResponseBytes: 1 << 20, RequestTimeout: 30 * time.Second, MaxRedirects: 2},
	}, wallet.Dependencies{HTTP: http.DefaultClient, Clock: wallet.ClockFunc(time.Now), Random: randReader{}})
	if err != nil {
		return nil, newError(CodeInternal, err)
	}
	return w, nil
}

// asError keeps an *Error err carries, or makes one with code.
func asError(code string, err error) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return newError(code, err)
}

// verifyES256 checks a compact JWS's ES256 signature under pub.
func verifyES256(compact string, pub *ecdsa.PublicKey) error {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return errors.New("malformed ES256 signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return errors.New("the JWS signature doesn't verify")
	}
	return nil
}
