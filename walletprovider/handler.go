package walletprovider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// Handler serves the provider's HTTP protocol, version 1: JSON over
// POST, each path relative to where it's mounted.
//
//	POST ChallengePath         {"purpose"}                                  → 200 {"challenge","purpose","expires_at"}
//	POST InstancesPath         {"challenge","instance_key","evidence"}      → 201 {"instance_id"}
//	POST WalletAttestationPath {"client_id"}                         signed → 200 {"wallet_attestation"}
//	POST KeyAttestationPath    {"challenge","keys","evidence","nonce"} signed → 200 {"key_attestation","expires_at"}
//	GET  StatusPath            the status list (StatusList), JWT or CWT by Accept
//
// "evidence" is {"kind","data"}, data base64url without padding (an
// array of them in a Key Attestation request); "instance_key" and
// "keys" are public JWKs. The two signed requests carry SignRequest's
// JWT, over the request's method, path and body and a challenge issued
// for PurposeRequest, in the RequestHeader header; its sub names the
// instance. Client speaks the protocol, and mobile/WALLET_PROVIDER.md
// in the repository documents it for a client in another language.
//
// Request bodies are application/json, at most MaxRequestBytes, and
// decoded strictly: a member the request doesn't define, a duplicate
// member, or data after the object is refused. A refusal is a JSON
// object {"error","error_description"} whose error is one of the
// protocol's codes and whose description is fixed text: the internal
// error is logged (Dependencies.Logger), never sent. A signed request
// that doesn't verify — its JWT malformed or stale, its signature not
// the instance key's, its challenge unknown or used, its instance
// unknown — is answered with one and the same 401, so it can't tell
// an unknown instance from a wrong key, and it doesn't use up the
// challenge it names.
//
// The path a signed request covers is the one the client sent
// (the request's RequestURI), so Handler may be mounted under a prefix
// with http.StripPrefix; a proxy in front of it must not rewrite paths.
//
// Handler does no rate limiting: wrap it with the deployment's own.
// ChallengePath and InstancesPath answer anyone, and every challenge
// is stored until it's used or expires, so limit them per client.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+ChallengePath, p.serveChallenge)
	mux.HandleFunc("POST "+InstancesPath, p.serveRegister)
	mux.HandleFunc("POST "+WalletAttestationPath, p.serveWalletAttestation)
	mux.HandleFunc("POST "+KeyAttestationPath, p.serveKeyAttestation)
	mux.Handle("GET "+StatusPath, p.publisher)
	return mux
}

// apiError is a refusal as the protocol answers it.
type apiError struct {
	status      int
	code        string
	description string
}

// The protocol's refusals.
var (
	errMalformed     = apiError{http.StatusBadRequest, "invalid_request", "The request is malformed."}
	errTooLarge      = apiError{http.StatusRequestEntityTooLarge, "invalid_request", "The request body is too large."}
	errMediaType     = apiError{http.StatusUnsupportedMediaType, "invalid_request", "The request body must be application/json."}
	errUnauthorized  = apiError{http.StatusUnauthorized, "invalid_signed_request", "The signed request didn't verify."}
	errBadChallenge  = apiError{http.StatusBadRequest, "invalid_challenge", "The challenge is unknown, used, expired, or for another purpose."}
	errNoEvidence    = apiError{http.StatusBadRequest, "evidence_required", "Platform evidence is required."}
	errEvidenceKind  = apiError{http.StatusBadRequest, "unsupported_evidence", "The evidence kind isn't supported."}
	errRejected      = apiError{http.StatusForbidden, "evidence_rejected", "The evidence didn't verify."}
	errPolicy        = apiError{http.StatusForbidden, "policy_refused", "The provider's policy refuses the evidence."}
	errNotActive     = apiError{http.StatusForbidden, "instance_not_active", "The instance is suspended."}
	errRevoked       = apiError{http.StatusForbidden, "instance_revoked", "The instance is revoked."}
	errKeyRegistered = apiError{http.StatusConflict, "instance_key_registered", "The instance key is already registered."}
	errUnknownClient = apiError{http.StatusBadRequest, "unknown_client", "The provider doesn't attest that client."}
	errNoKeyAttested = apiError{http.StatusForbidden, "no_key_attested", "No key could be attested."}
	errServer        = apiError{http.StatusInternalServerError, "server_error", "The provider couldn't answer."}
)

// errDecoding wraps why a request body was refused, for the log.
var errDecoding = errors.New("walletprovider: decoding the request")

// refusal maps an error from a Provider method to the protocol's
// answer. Anything that isn't one of the documented refusals is the
// provider's own failure.
func refusal(err error) apiError {
	// Order matters: some errors wrap others (ErrNoKeyAttested the
	// last evidence error, ErrInstanceRevoked ErrInstanceNotActive).
	for _, m := range []struct {
		err error
		api apiError
	}{
		{ErrNoKeyAttested, errNoKeyAttested},
		{ErrInstanceKeyRegistered, errKeyRegistered},
		{ErrInstanceRevoked, errRevoked},
		{ErrInstanceNotActive, errNotActive},
		{ErrInstanceNotFound, errUnauthorized},
		{ErrUnknownClient, errUnknownClient},
		{ErrChallenge, errBadChallenge},
		{ErrEvidenceRequired, errNoEvidence},
		{ErrEvidenceKind, errEvidenceKind},
		{ErrPolicy, errPolicy},
		{ErrEvidenceRejected, errRejected},
		{ErrInvalidRequest, errMalformed},
	} {
		if errors.Is(err, m.err) {
			return m.api
		}
	}
	return errServer
}

func (p *Provider) serveChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequestBody
	if !p.readJSON(w, r, &req) {
		return
	}
	c, err := p.Challenge(r.Context(), req.Purpose)
	if err != nil {
		p.fail(r, w, refusal(err), err)
		return
	}
	writeJSON(w, http.StatusOK, challengeResponseBody{Challenge: c.Value, Purpose: c.Purpose, ExpiresAt: c.ExpiresAt.Unix()})
}

func (p *Provider) serveRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequestBody
	if !p.readJSON(w, r, &req) {
		return
	}
	key, err := jwk.ParsePublicKey(req.InstanceKey)
	if err != nil {
		p.fail(r, w, errMalformed, fmt.Errorf("instance_key: %w", err))
		return
	}
	ev, err := req.Evidence.evidence()
	if err != nil {
		p.fail(r, w, errMalformed, err)
		return
	}
	in, err := p.Register(r.Context(), RegisterRequest{Challenge: req.Challenge, InstanceKey: key, Evidence: ev})
	if err != nil {
		p.fail(r, w, refusal(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, registerResponseBody{InstanceID: in.ID})
}

func (p *Provider) serveWalletAttestation(w http.ResponseWriter, r *http.Request) {
	var req walletAttestationRequestBody
	in, ok := p.readSigned(w, r, &req)
	if !ok {
		return
	}
	jwt, err := p.WalletAttestation(r.Context(), WalletAttestationRequest{InstanceID: in.ID, ClientID: req.ClientID})
	if err != nil {
		p.fail(r, w, refusal(err), err)
		return
	}
	writeJSON(w, http.StatusOK, walletAttestationResponseBody{WalletAttestation: jwt})
}

func (p *Provider) serveKeyAttestation(w http.ResponseWriter, r *http.Request) {
	var req keyAttestationRequestBody
	in, ok := p.readSigned(w, r, &req)
	if !ok {
		return
	}
	if len(req.Keys) > p.cfg.Policy.maxKeys() || len(req.Evidence) > p.cfg.Policy.maxKeys() {
		p.fail(r, w, errMalformed, fmt.Errorf("%d keys and %d pieces of evidence, more than %d", len(req.Keys), len(req.Evidence), p.cfg.Policy.maxKeys()))
		return
	}
	kr := KeyAttestationRequest{InstanceID: in.ID, Challenge: req.Challenge, Nonce: req.Nonce}
	for i, raw := range req.Keys {
		key, err := jwk.ParsePublicKey(raw)
		if err != nil {
			p.fail(r, w, errMalformed, fmt.Errorf("keys[%d]: %w", i, err))
			return
		}
		kr.Keys = append(kr.Keys, key)
	}
	for i, e := range req.Evidence {
		ev, err := e.evidence()
		if err != nil {
			p.fail(r, w, errMalformed, fmt.Errorf("evidence[%d]: %w", i, err))
			return
		}
		kr.Evidence = append(kr.Evidence, ev)
	}
	res, err := p.KeyAttestation(r.Context(), kr)
	if err != nil {
		p.fail(r, w, refusal(err), err)
		return
	}
	writeJSON(w, http.StatusOK, keyAttestationResponseBody{KeyAttestation: res.JWT, ExpiresAt: res.ExpiresAt.Unix()})
}

// evidence decodes e. Absent evidence decodes to the zero Evidence,
// which the Provider refuses with ErrEvidenceRequired.
func (e evidenceBody) evidence() (Evidence, error) {
	data, err := base64.RawURLEncoding.DecodeString(e.Data)
	if err != nil {
		return Evidence{}, fmt.Errorf("%w: evidence data isn't base64url: %w", ErrInvalidRequest, err)
	}
	return Evidence{Kind: e.Kind, Data: data}, nil
}

// readJSON reads r's body into v, as readBody and decodeBody do.
func (p *Provider) readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body, ok := p.readBody(w, r)
	return ok && p.decodeBody(w, r, body, v)
}

// readBody reads r's body, application/json of at most
// MaxRequestBytes; it answers the refusal itself and reports false if
// it can't.
func (p *Provider) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		p.fail(r, w, errMediaType, fmt.Errorf("%w: content type %q", errDecoding, r.Header.Get("Content-Type")))
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			p.fail(r, w, errTooLarge, err)
		} else {
			p.fail(r, w, errMalformed, fmt.Errorf("%w: %w", errDecoding, err))
		}
		return nil, false
	}
	return body, true
}

// decodeBody decodes body into v strictly (decodeStrict), answering
// the refusal itself and reporting false if it can't.
func (p *Provider) decodeBody(w http.ResponseWriter, r *http.Request, body []byte, v any) bool {
	if err := decodeStrict(body, v); err != nil {
		p.fail(r, w, errMalformed, fmt.Errorf("%w: %w", errDecoding, err))
		return false
	}
	return true
}

// readSigned reads a signed request's body, verifies its RequestHeader
// over it (VerifyRequest), and only then decodes it into v, returning
// the instance it comes from. Every way the signed request can fail to
// verify gets the one 401.
func (p *Provider) readSigned(w http.ResponseWriter, r *http.Request, v any) (Instance, bool) {
	signed := r.Header.Values(RequestHeader)
	if len(signed) != 1 || signed[0] == "" || len(signed[0]) > maxSignedRequestBytes {
		p.fail(r, w, errUnauthorized, fmt.Errorf("%w: %d %s headers", ErrInvalidRequest, len(signed), RequestHeader))
		return Instance{}, false
	}
	body, ok := p.readBody(w, r)
	if !ok {
		return Instance{}, false
	}
	path, err := requestPath(r)
	if err != nil {
		p.fail(r, w, errUnauthorized, err)
		return Instance{}, false
	}
	in, err := p.VerifyRequest(r.Context(), Request{JWT: signed[0], Method: r.Method, Path: path, Body: body})
	switch {
	case err == nil:
		return in, p.decodeBody(w, r, body, v)
	case errors.Is(err, ErrInstanceRevoked):
		p.fail(r, w, errRevoked, err)
	case errors.Is(err, ErrInstanceNotActive):
		p.fail(r, w, errNotActive, err)
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInstanceNotFound), errors.Is(err, ErrChallenge):
		p.fail(r, w, errUnauthorized, err)
	default:
		p.fail(r, w, errServer, err)
	}
	return Instance{}, false
}

// requestPath is the path r was sent to, as the client sent it: a
// prefix http.StripPrefix removed from r.URL is still there.
func requestPath(r *http.Request) (string, error) {
	u, err := url.ParseRequestURI(r.RequestURI)
	if err != nil {
		return "", fmt.Errorf("%w: request URI: %w", ErrInvalidRequest, err)
	}
	return u.EscapedPath(), nil
}

// fail answers a, logging err: at error level for the provider's own
// failure, info for a refusal.
func (p *Provider) fail(r *http.Request, w http.ResponseWriter, a apiError, err error) {
	level := slog.LevelInfo
	if a.status >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	p.logger().LogAttrs(context.WithoutCancel(r.Context()), level, "walletprovider: request refused",
		slog.String("path", r.URL.Path), slog.Int("status", a.status), slog.String("error_code", a.code), slog.Any("error", err))
	if a.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", RequestHeader)
	}
	writeJSON(w, a.status, errorBody{Error: a.code, Description: a.description})
}

func (p *Provider) logger() *slog.Logger {
	if p.deps.Logger != nil {
		return p.deps.Logger
	}
	return slog.Default()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		status, body = http.StatusInternalServerError, []byte(`{"error":"server_error"}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
