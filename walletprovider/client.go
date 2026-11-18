package walletprovider

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// DefaultClientTimeout bounds each request a Client makes when its HTTP
// client sets no Timeout.
const DefaultClientTimeout = 30 * time.Second

// headerContentType and mediaTypeJSON are the Content-Type header and
// the JSON media type the Wallet Provider API sends and expects.
const (
	headerContentType = "Content-Type"
	mediaTypeJSON     = "application/json"
)

// ErrRefused is wrapped by the error a Client returns when the provider
// answers with one of the protocol's refusals; errors.As finds the
// *RefusedError with its code.
var ErrRefused = errors.New("walletprovider: the provider refused the request")

// RefusedError is a refusal the provider answered with.
type RefusedError struct {
	// Status is the HTTP status code.
	Status int
	// Code is the protocol's error code ("evidence_rejected", ...), and
	// Description the provider's text for it.
	Code        string
	Description string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("walletprovider: the provider refused the request: HTTP %d %s: %s", e.Status, e.Code, e.Description)
}

// Unwrap makes a RefusedError match ErrRefused.
func (e *RefusedError) Unwrap() error { return ErrRefused }

// The refusal codes that tell a wallet fresh evidence recovers it: the
// provider no longer relies on evidence it kept (ErrEvidenceExpired).
const (
	// CodeRegistrationExpired: register again (ErrRegistrationExpired).
	CodeRegistrationExpired = "registration_expired"
	// CodeInstanceKeyExpired: attest a new instance key, with fresh
	// evidence (ErrInstanceKeyExpired).
	CodeInstanceKeyExpired = "instance_key_expired"
)

// CodeInstanceKeyRegistered is the refusal of a key that's already
// another's (ErrInstanceKeyRegistered): among others, an instance key
// recorded for an instance the wallet no longer has, as after it
// registered again.
const CodeInstanceKeyRegistered = "instance_key_registered"

// CodeEvidenceRequired is the refusal of a request that sent no evidence
// where the provider needs it (ErrEvidenceRequired): among others, a
// Wallet Attestation for an instance key whose record the provider has
// deleted (Config.InstanceKeyRetention). A wallet whose evidence binds
// the challenge into the key's own attestation, as Android Key
// Attestation does, can't make it for that key again.
const CodeEvidenceRequired = "evidence_required"

// CodeError is the error a refusal with the protocol's error code code
// matches (errors.Is): ErrRegistrationExpired for
// CodeRegistrationExpired, ErrInstanceKeyExpired for
// CodeInstanceKeyExpired, ErrInstanceKeyRegistered for
// CodeInstanceKeyRegistered, ErrEvidenceRequired for
// CodeEvidenceRequired, as the Provider's own errors do; nil for any
// other code. A RefusedError matches it at the code's status
// (CodeStatus), and a wallet whose provider client isn't this package's
// (a native one, say) can wrap it in its own refusal, so that walletflow
// tells what the refusal means for an instance key the same way: only
// for an answer with that status, since walletflow forgets a refresh
// grant on it.
func CodeError(code string) error {
	switch code {
	case CodeRegistrationExpired:
		return ErrRegistrationExpired
	case CodeInstanceKeyExpired:
		return ErrInstanceKeyExpired
	case CodeInstanceKeyRegistered:
		return ErrInstanceKeyRegistered
	case CodeEvidenceRequired:
		return ErrEvidenceRequired
	}
	return nil
}

// CodeStatus is the HTTP status Provider.Handler answers a refusal with
// code with, for the codes CodeError names an error for and
// "instance_revoked": 403, 409 for CodeInstanceKeyRegistered, 400 for
// CodeEvidenceRequired; 0 for any other code. A client acts on these
// codes, which discard a registration or a refresh grant, only at that
// status: an answer with another — a redirect, or a proxy's page in
// front of the provider — isn't the provider's refusal.
func CodeStatus(code string) int {
	switch code {
	case CodeRegistrationExpired, CodeInstanceKeyExpired, "instance_revoked":
		return http.StatusForbidden
	case CodeInstanceKeyRegistered:
		return http.StatusConflict
	case CodeEvidenceRequired:
		return http.StatusBadRequest
	}
	return 0
}

// Is makes a RefusedError match the error its code does (CodeError), at
// the code's status (CodeStatus), so a wallet can tell what to send
// fresh evidence for with errors.Is.
func (e *RefusedError) Is(target error) bool {
	sentinel := CodeError(e.Code)
	return sentinel != nil && target == sentinel && e.Status == CodeStatus(e.Code)
}

// Client speaks the provider's HTTP protocol (Provider.Handler) for a
// wallet written in Go: it gets challenges, registers an instance, and
// asks for attestations with requests signed by the instance's
// registration key (SignRequest). It follows no redirect, so a request
// is never resent to a host other than the provider, and reads at most
// a bounded response. Create one with NewClient; it is safe for
// concurrent use.
type Client struct {
	base  *url.URL
	http  *http.Client
	clock func() time.Time
}

// ClientOptions are a Client's optional settings.
type ClientOptions struct {
	// HTTP makes the requests. nil means one from fapihttp.NewClient
	// with fapihttp.RecommendedTransportConfig(): https only, to public
	// addresses only. Build any other with fapihttp.NewClient too,
	// which is what keeps a request off private addresses. Its Timeout,
	// if zero, is DefaultClientTimeout, and its redirect policy is
	// replaced by one that follows none.
	HTTP *http.Client

	// Clock is the time signed requests are made at; nil means
	// time.Now.
	Clock func() time.Time
}

// NewClient returns a Client for the provider whose Handler is served
// at baseURL, an absolute https URL: the protocol's paths are appended
// to its path.
func NewClient(baseURL string, opts ClientOptions) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("walletprovider: the provider URL %q isn't an absolute https URL without userinfo, query or fragment", baseURL)
	}
	hc := opts.HTTP
	if hc == nil {
		if hc, err = fapihttp.NewClient(fapihttp.RecommendedTransportConfig()); err != nil {
			return nil, fmt.Errorf("walletprovider: building the HTTP client: %w", err)
		}
	}
	copied := *hc
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if copied.Timeout <= 0 {
		copied.Timeout = DefaultClientTimeout
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return &Client{base: u, http: &copied, clock: clock}, nil
}

// Challenge asks for a challenge for purpose.
func (c *Client) Challenge(ctx context.Context, purpose Purpose) (Challenge, error) {
	var resp challengeResponseBody
	if err := c.post(ctx, ChallengePath, challengeRequestBody{Purpose: purpose}, nil, http.StatusOK, &resp); err != nil {
		return Challenge{}, err
	}
	if resp.Challenge == "" || resp.Purpose != purpose {
		return Challenge{}, errors.New("walletprovider: the provider answered with a challenge for another purpose")
	}
	return Challenge{Value: resp.Challenge, Purpose: resp.Purpose, ExpiresAt: time.Unix(resp.ExpiresAt, 0)}, nil
}

// Register registers an instance: req.Challenge is a challenge for
// PurposeRegistration, which req.Evidence is bound to. It returns the
// instance ID, which later requests name with the registration key's
// signature.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (string, error) {
	key, err := marshalKey(req.RegistrationKey)
	if err != nil {
		return "", err
	}
	body := registerRequestBody{Challenge: req.Challenge, RegistrationKey: wireJWK{JWK: key.jwk}, Evidence: evidenceBodyOf(req.Evidence)}
	var resp registerResponseBody
	if err := c.post(ctx, InstancesPath, body, nil, http.StatusCreated, &resp); err != nil {
		return "", err
	}
	if resp.InstanceID == "" {
		return "", errors.New("walletprovider: the provider answered with no instance ID")
	}
	return resp.InstanceID, nil
}

// WalletAttestation asks for a Wallet Attestation for req.ClientID and
// the instance key req.InstanceKey, signing the request with
// registrationKey, req.InstanceID's registration key. The first time
// it's asked for an instance key, req.Challenge (a challenge for
// PurposeInstance) and req.Evidence, vouching for the key, are
// required; afterwards they may be left out. It gets a PurposeRequest
// challenge first. The attestation's sub and cnf are checked to be the
// client and req.InstanceKey; its signature is the issuer's to verify.
func (c *Client) WalletAttestation(ctx context.Context, registrationKey crypto.Signer, req WalletAttestationRequest) (string, error) {
	key, err := marshalKey(req.InstanceKey)
	if err != nil {
		return "", err
	}
	body := walletAttestationRequestBody{ClientID: req.ClientID, InstanceKey: wireJWK{JWK: key.jwk}, Challenge: req.Challenge}
	if req.Evidence.Kind != "" || len(req.Evidence.Data) > 0 {
		ev := evidenceBodyOf(req.Evidence)
		body.Evidence = &ev
	}
	var resp walletAttestationResponseBody
	if err := c.postSigned(ctx, registrationKey, req.InstanceID, WalletAttestationPath, body, &resp); err != nil {
		return "", err
	}
	var claims struct {
		Subject string `json:"sub"`
		Cnf     struct {
			JWK json.RawMessage `json:"jwk"`
		} `json:"cnf"`
	}
	if err := unverifiedClaims(resp.WalletAttestation, &claims); err != nil {
		return "", fmt.Errorf("walletprovider: the Wallet Attestation: %w", err)
	}
	if ok, err := jwk.Matches(claims.Cnf.JWK, req.InstanceKey); err != nil || !ok || claims.Subject != req.ClientID {
		return "", fmt.Errorf("walletprovider: the Wallet Attestation isn't for client %q and the instance key", req.ClientID)
	}
	return resp.WalletAttestation, nil
}

// KeyAttestation asks for a Key Attestation over req.Keys, for the
// issuance of req.InstanceKey (an instance key a Wallet Attestation
// recorded), signing the request with registrationKey, req.InstanceID's
// registration key: req.Challenge is a challenge for PurposeHolder,
// which every piece of req.Evidence is bound to. It gets a
// PurposeRequest challenge for the signature first.
// The result's AttestedKeys are the keys the provider attested, which
// may be fewer than req.Keys; its nonce is checked to be req.Nonce.
// Its KeyStorage and UserAuthentication are the JWT's claims, read
// without verifying its signature, which is the issuer's to verify.
func (c *Client) KeyAttestation(ctx context.Context, registrationKey crypto.Signer, req KeyAttestationRequest) (KeyAttestationResult, error) {
	ik, err := marshalKey(req.InstanceKey)
	if err != nil {
		return KeyAttestationResult{}, fmt.Errorf("the instance key: %w", err)
	}
	body := keyAttestationRequestBody{InstanceKey: wireJWK{JWK: ik.jwk}, Challenge: req.Challenge, Nonce: req.Nonce}
	for i, k := range req.Keys {
		mk, err := marshalKey(k)
		if err != nil {
			return KeyAttestationResult{}, fmt.Errorf("key %d: %w", i, err)
		}
		body.Keys = append(body.Keys, wireJWK{JWK: mk.jwk})
	}
	for _, e := range req.Evidence {
		body.Evidence = append(body.Evidence, evidenceBodyOf(e))
	}
	var resp keyAttestationResponseBody
	if err := c.postSigned(ctx, registrationKey, req.InstanceID, KeyAttestationPath, body, &resp); err != nil {
		return KeyAttestationResult{}, err
	}
	var claims struct {
		Nonce              string                                  `json:"nonce"`
		AttestedKeys       []json.RawMessage                       `json:"attested_keys"`
		KeyStorage         []attestation.AttackPotentialResistance `json:"key_storage"`
		UserAuthentication []attestation.AttackPotentialResistance `json:"user_authentication"`
	}
	if err := unverifiedClaims(resp.KeyAttestation, &claims); err != nil {
		return KeyAttestationResult{}, fmt.Errorf("walletprovider: the Key Attestation: %w", err)
	}
	if claims.Nonce != req.Nonce || len(claims.AttestedKeys) == 0 {
		return KeyAttestationResult{}, errors.New("walletprovider: the Key Attestation isn't over the nonce sent, or attests no key")
	}
	result := KeyAttestationResult{
		JWT: resp.KeyAttestation, ExpiresAt: time.Unix(resp.ExpiresAt, 0),
		KeyStorage: claims.KeyStorage, UserAuthentication: claims.UserAuthentication,
	}
	for _, raw := range claims.AttestedKeys {
		got, err := jwk.ParsePublicKey(raw)
		if err != nil {
			return KeyAttestationResult{}, fmt.Errorf("walletprovider: the Key Attestation's attested_keys: %w", err)
		}
		i := slices.IndexFunc(req.Keys, func(k crypto.PublicKey) bool { return certchain.SameKey(k, got) })
		if i < 0 {
			return KeyAttestationResult{}, errors.New("walletprovider: the Key Attestation attests a key that wasn't sent")
		}
		result.AttestedKeys = append(result.AttestedKeys, req.Keys[i])
	}
	return result, nil
}

func evidenceBodyOf(e Evidence) evidenceBody {
	return evidenceBody{Kind: e.Kind, Data: base64.RawURLEncoding.EncodeToString(e.Data)}
}

// unverifiedClaims decodes a compact JWS's payload into v without
// verifying it: a check that the provider answered what was asked.
func unverifiedClaims(compact string, v any) error {
	_, payload, err := jose.DecodeUnverified(compact)
	if err != nil {
		return err
	}
	return strictjson.Unmarshal(payload, v)
}

// postSigned gets a PurposeRequest challenge, then posts body to path
// signed with registrationKey for instanceID.
func (c *Client) postSigned(ctx context.Context, registrationKey crypto.Signer, instanceID, path string, body, out any) error {
	if registrationKey == nil || instanceID == "" {
		return fmt.Errorf("%w: the instance ID and registration key are required", ErrInvalidRequest)
	}
	ch, err := c.Challenge(ctx, PurposeRequest)
	if err != nil {
		return err
	}
	return c.post(ctx, path, body, func(target *url.URL, payload []byte) (string, error) {
		return SignRequest(registrationKey, instanceID, ch.Value, http.MethodPost, target.EscapedPath(), payload, c.clock())
	}, http.StatusOK, out)
}

// post posts body as JSON to path, signing it with sign if set, and
// decodes the answer, which must have status want, into out.
func (c *Client) post(ctx context.Context, path string, body any, sign func(*url.URL, []byte) (string, error), want int, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("walletprovider: marshal request: %w", err)
	}
	target := *c.base
	target.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("walletprovider: %w", err)
	}
	req.Header.Set(headerContentType, mediaTypeJSON)
	req.Header.Set("Accept", mediaTypeJSON)
	if sign != nil {
		jwt, err := sign(&target, payload)
		if err != nil {
			return err
		}
		req.Header.Set(RequestHeader, jwt)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("walletprovider: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("walletprovider: %s: reading the response: %w", path, err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("walletprovider: %s: the response is larger than %d bytes", path, maxResponseBytes)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get(headerContentType)); err != nil || mt != mediaTypeJSON {
		return fmt.Errorf("walletprovider: %s: HTTP %d with content type %q", path, resp.StatusCode, resp.Header.Get(headerContentType))
	}
	if resp.StatusCode != want {
		var e errorBody
		if err := json.Unmarshal(data, &e); err != nil || e.Error == "" {
			return fmt.Errorf("walletprovider: %s: HTTP %d", path, resp.StatusCode)
		}
		return &RefusedError{Status: resp.StatusCode, Code: e.Error, Description: e.Description}
	}
	if err := strictjson.Unmarshal(data, out); err != nil {
		return fmt.Errorf("walletprovider: %s: malformed response: %w", path, err)
	}
	return nil
}
