package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"

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
	// object.)
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
}

// keyStore is a KeyStore as a walletflow.KeyStore.
type keyStore struct{ ks KeyStore }

var _ walletflow.KeyStore = keyStore{}

func (k keyStore) NewKey(_ context.Context, purpose walletflow.KeyPurpose) (walletflow.Key, error) {
	id, err := k.ks.CreateKey(string(purpose))
	if err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("new %s key: %w", purpose, err))
	}
	if id == "" {
		return nil, newError(CodePlatform, fmt.Errorf("new %s key: no key ID", purpose))
	}
	key, err := k.load(id)
	if errors.Is(err, walletflow.ErrNotFound) {
		return nil, newError(CodePlatform, fmt.Errorf("new %s key %q isn't in the key store", purpose, id))
	}
	return key, err
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
	return &platformKey{ks: k.ks, id: id, pub: pub}, nil
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
	id  string
	pub *ecdsa.PublicKey
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

// DPoPProof returns a DPoP proof (RFC 9449) for a request with method
// htm to htu, signed with store's key keyID.
func DPoPProof(store KeyStore, keyID, htm, htu string) (string, error) {
	if store == nil {
		return "", newError(CodeInvalidInput, errors.New("no key store"))
	}
	key, err := keyStore{store}.load(keyID)
	if err != nil {
		return "", err
	}
	w, err := newCoreWallet()
	if err != nil {
		return "", err
	}
	proof, err := w.GenerateDPoPProof(key, htm, htu, "", "")
	if err != nil {
		return "", asError(CodeInvalidInput, err)
	}
	return proof, nil
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
	ks := keyStore{store}
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
	km, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.DPoPProofSigning: key},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.DPoPProofSigning: fapi.ES256}, nil)
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

// newCoreWallet returns the wallet package's Wallet, for the protocol
// messages the spike builds.
func newCoreWallet() (*wallet.Wallet, error) {
	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: "ES256",
		Fetch: fapihttp.Config{MaxResponseBytes: maxFetchBytes, RequestTimeout: 30 * time.Second, MaxRedirects: 2},
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
