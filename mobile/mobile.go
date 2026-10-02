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
	"sync"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// ABIVersion is the version of this package's API across the gomobile
// boundary: its functions, objects, JSON results and error codes. It
// changes whenever any of them changes incompatibly.
const ABIVersion = 0

// Error codes, at the start of every error's text in brackets.
const (
	// CodeInvalidInput: an argument was malformed.
	CodeInvalidInput = "invalid_input"
	// CodePlatform: a callback into the app failed.
	CodePlatform = "platform"
	// CodeNetwork: a request failed or got an unexpected answer.
	CodeNetwork = "network"
	// CodeCancelled: the Operation was cancelled.
	CodeCancelled = "cancelled"
	// CodeInternal: anything else.
	CodeInternal = "internal"
)

// Error is an error as it crosses the boundary: its text is
// "[Code] Message".
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return "[" + e.Code + "] " + e.Message }

func newError(code string, err error) error {
	return &Error{Code: code, Message: err.Error()}
}

// result is the JSON envelope's common part.
type result struct {
	ABI int `json:"abi"`
}

// ParseRequestLink parses an OpenID4VP request link (openid4vp://?…) and
// returns {"abi", "client_id", "request_uri", "request_uri_method"}.
func ParseRequestLink(link string) (string, error) {
	parsed, err := wallet.ParseAuthorizationRequestLink(link)
	if err != nil {
		return "", newError(CodeInvalidInput, err)
	}
	out, err := json.Marshal(struct {
		result
		ClientID         string `json:"client_id"`
		RequestURI       string `json:"request_uri"`
		RequestURIMethod string `json:"request_uri_method,omitempty"`
	}{result{ABIVersion}, parsed.ClientID, parsed.RequestURI, parsed.RequestURIMethod})
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	return string(out), nil
}

// Signer is a P-256 key the app holds — in the Secure Enclave, say —
// that never leaves it.
type Signer interface {
	// PublicKey returns the key's public key as an uncompressed X9.63
	// point (0x04 || X || Y), as CryptoKit's x963Representation.
	PublicKey() ([]byte, error)
	// Sign signs a SHA-256 digest, returning an ASN.1 DER ECDSA
	// signature, as CryptoKit's derRepresentation.
	Sign(digest []byte) ([]byte, error)
}

// platformSigner is a Signer as a crypto.Signer.
type platformSigner struct {
	s   Signer
	pub *ecdsa.PublicKey
}

func newPlatformSigner(s Signer) (*platformSigner, error) {
	if s == nil {
		return nil, newError(CodeInvalidInput, errors.New("no signer"))
	}
	raw, err := s.PublicKey()
	if err != nil {
		return nil, newError(CodePlatform, err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, newError(CodePlatform, fmt.Errorf("public key: %w", err))
	}
	return &platformSigner{s: s, pub: pub}, nil
}

func (p *platformSigner) Public() crypto.PublicKey { return p.pub }

func (p *platformSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("mobile: platform keys sign SHA-256 digests only, not %v", opts.HashFunc())
	}
	sig, err := p.s.Sign(digest)
	if err != nil {
		return nil, newError(CodePlatform, err)
	}
	if !ecdsa.VerifyASN1(p.pub, digest, sig) {
		return nil, newError(CodePlatform, errors.New("the signature doesn't verify under the key's public key"))
	}
	return sig, nil
}

// DPoPProof returns a DPoP proof (RFC 9449) for a request with method
// htm to htu, signed by signer through the app, and checked here.
func DPoPProof(signer Signer, htm, htu string) (string, error) {
	ps, err := newPlatformSigner(signer)
	if err != nil {
		return "", err
	}
	w, err := wallet.New(wallet.Config{
		Assurance: wallet.AssuranceDevelopment, ProofSigningAlg: "ES256",
		Fetch: fapihttp.Config{MaxResponseBytes: maxFetchBytes, RequestTimeout: 30 * time.Second, MaxRedirects: 2},
	}, wallet.Dependencies{
		HTTP: http.DefaultClient, Clock: wallet.ClockFunc(time.Now), Random: randReader{},
	})
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	proof, err := w.GenerateDPoPProof(ps, htm, htu, "", "")
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return "", e
		}
		return "", newError(CodeInvalidInput, err)
	}
	if err := verifyES256(proof, ps.pub); err != nil {
		return "", newError(CodeInternal, err)
	}
	return proof, nil
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
		return errors.New("the proof's signature doesn't verify")
	}
	return nil
}

// Operation is a long call the app can cancel from another thread.
type Operation struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewOperation returns an Operation that times out after timeoutMillis
// (0: never).
func NewOperation(timeoutMillis int64) *Operation {
	if timeoutMillis > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMillis)*time.Millisecond)
		return &Operation{ctx: ctx, cancel: cancel}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Operation{ctx: ctx, cancel: cancel}
}

// Cancel cancels the operation: a call using it returns a "cancelled"
// error. Safe to call more than once, and from any thread.
func (o *Operation) Cancel() { o.cancel() }

// fetcher is the spike's shared HTTP client.
var fetcher = struct {
	sync.Once
	c *http.Client
}{}

func httpClient() *http.Client {
	fetcher.Do(func() { fetcher.c = &http.Client{Timeout: 30 * time.Second} })
	return fetcher.c
}

// maxFetchBytes bounds what Fetch reads.
const maxFetchBytes = 1 << 20

// Fetch GETs url under op and returns its body as text — the spike's
// stand-in for a protocol request the app can cancel.
func Fetch(op *Operation, url string) (string, error) {
	if op == nil {
		return "", newError(CodeInvalidInput, errors.New("no operation"))
	}
	req, err := http.NewRequestWithContext(op.ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", newError(CodeInvalidInput, err)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		if op.ctx.Err() != nil {
			return "", newError(CodeCancelled, op.ctx.Err())
		}
		return "", newError(CodeNetwork, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		if op.ctx.Err() != nil {
			return "", newError(CodeCancelled, op.ctx.Err())
		}
		return "", newError(CodeNetwork, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", newError(CodeNetwork, fmt.Errorf("status %d", resp.StatusCode))
	}
	return string(body), nil
}
