package verifierapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// Config configures an App.
type Config struct {
	// VerifierURL is the base of this verifier's endpoints; must be
	// https (the response_uri a wallet posts to).
	VerifierURL string

	// IssuerVCT is the vct the demo issuer's SD-JWT credentials carry
	// (its issuer URL + "/vct/passport/1").
	IssuerVCT string

	// IssuerRoots holds the demo issuer's CA — the trust anchor for
	// credential issuer signatures, in both trust modes.
	IssuerRoots *x509.CertPool

	// CSCAPool verifies the raw SOD/DG1 in ModeICAO —
	// cms.DefaultMasterList for real passports.
	CSCAPool cms.CertPool

	// RequestLifetime bounds how long a presentation request stays
	// answerable; zero means 10 minutes.
	RequestLifetime time.Duration
}

// App is a running passport-vdc verifier.
type App struct {
	cfg      Config
	verifier *verifier.Verifier
	now      func() time.Time
	handler  http.Handler

	mu       sync.Mutex
	sessions map[string]*session // by request ID (also the OpenID4VP state)
	byKeyID  map[string]string   // response encryption key ID → request ID
}

type session struct {
	mode          Mode
	query         dcql.Query
	nonce         string
	requestObject string
	decryptionKey *ecdsa.PrivateKey
	link          string
	expiresAt     time.Time
	outcome       *Outcome
}

// Outcome is what a verified presentation established.
type Outcome struct {
	Mode Mode
	// Format is the credential format the wallet chose to present.
	Format string
	// Claims are the credential's verified, disclosed claims (ModeIssuer).
	Claims map[string]any
	// ICAO is the Passive Authentication result over the disclosed SOD
	// and DG1 (ModeICAO).
	ICAO *ICAOResult
	// Error is set when the presentation was rejected.
	Error string
}

// ICAOResult is a ModeICAO check of the raw data groups.
type ICAOResult struct {
	Verified bool
	Identity passport.Identity
	Error    string
}

// New wires an App. Its request-signing key and certificate (the
// x509_hash client identifier) are generated per process.
func New(cfg Config) (*App, error) {
	if cfg.VerifierURL == "" || cfg.IssuerVCT == "" || cfg.IssuerRoots == nil || cfg.CSCAPool == nil {
		return nil, fmt.Errorf("verifierapp: VerifierURL, IssuerVCT, IssuerRoots and CSCAPool are required")
	}
	responseURI, err := fapi.ParseEndpointURL(cfg.VerifierURL + "/response")
	if err != nil {
		return nil, fmt.Errorf("verifierapp: response URI: %w", err)
	}
	key, cert, err := newRequestSigningIdentity()
	if err != nil {
		return nil, err
	}
	rec := haip.RecommendedVerifierConfig()
	v, err := verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI,
		SigningAlg: rec.SigningAlg, EncValuesSupported: rec.EncValuesSupported,
		VPFormatsSupported: mergeFormats(verifier.MdocFormatSupport(), verifier.SDJWTVCFormatSupport([]string{"ES256"}, []string{"ES256"})),
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	if err != nil {
		return nil, fmt.Errorf("verifierapp: verifier.New: %w", err)
	}
	a := &App{cfg: cfg, verifier: v, now: time.Now, sessions: map[string]*session{}, byKeyID: map[string]string{}}
	a.handler = a.routes()
	return a, nil
}

// ServeHTTP implements http.Handler.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.handler.ServeHTTP(w, r) }

func (a *App) lifetime() time.Duration {
	if a.cfg.RequestLifetime == 0 {
		return 10 * time.Minute
	}
	return a.cfg.RequestLifetime
}

// CreateRequest starts a presentation request in mode and returns its
// ID and the openid4vp:// link a wallet answers.
func (a *App) CreateRequest(mode Mode) (id, link string, err error) {
	query, err := buildQuery(mode, a.cfg.IssuerVCT)
	if err != nil {
		return "", "", err
	}
	id, err = randomID()
	if err != nil {
		return "", "", err
	}
	built, err := a.verifier.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query, State: id})
	if err != nil {
		return "", "", fmt.Errorf("verifierapp: build request: %w", err)
	}
	kid, err := responseKeyID(built.RequestObject)
	if err != nil {
		return "", "", err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, s := range a.sessions {
		if now.After(s.expiresAt) {
			delete(a.sessions, k)
		}
	}
	requestURI := a.cfg.VerifierURL + "/request-objects/" + id
	link = "openid4vp://?" + url.Values{"client_id": {a.verifier.ClientID()}, "request_uri": {requestURI}}.Encode()
	a.sessions[id] = &session{
		mode: mode, query: query, nonce: built.Nonce, requestObject: built.RequestObject,
		decryptionKey: built.ResponseDecryptionKey, link: link, expiresAt: now.Add(a.lifetime()),
	}
	a.byKeyID[kid] = id
	return id, link, nil
}

// Outcome returns request id's outcome, once a wallet has answered.
func (a *App) Outcome(id string) (*Outcome, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[id]
	if !ok || s.outcome == nil {
		return nil, false
	}
	return s.outcome, true
}

func (a *App) session(id string) (*session, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[id]
	if !ok || a.now().After(s.expiresAt) {
		return nil, false
	}
	return s, true
}

// handleRequestObject serves a request's signed Request Object at its
// request_uri.
func (a *App) handleRequestObject(w http.ResponseWriter, r *http.Request) {
	s, ok := a.session(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	_, _ = w.Write([]byte(s.requestObject))
}

// handleResponse is the response_uri: it routes the encrypted response
// to its request by the JWE's key ID, verifies it and records the
// outcome.
func (a *App) handleResponse(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, "invalid_request", "malformed response")
		return
	}
	responseJWE := r.PostForm.Get("response")
	kid, err := jweKeyID(responseJWE)
	if err != nil {
		writeJSONError(w, "invalid_request", "response is not a JWE with a key ID")
		return
	}
	a.mu.Lock()
	id := a.byKeyID[kid]
	delete(a.byKeyID, kid)
	a.mu.Unlock()
	s, ok := a.session(id)
	if !ok {
		writeJSONError(w, "invalid_request", "no pending request for this response")
		return
	}

	outcome := a.verify(r.Context(), s, id, responseJWE)
	a.mu.Lock()
	s.outcome = outcome
	a.mu.Unlock()
	if outcome.Error != "" {
		writeJSONError(w, "invalid_request", outcome.Error)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte("{}"))
}

// verify checks a response against its request. Errors are reported in
// the Outcome rather than returned.
func (a *App) verify(ctx context.Context, s *session, id, responseJWE string) *Outcome {
	out := &Outcome{Mode: s.mode}
	parsed, err := a.verifier.ParseDirectPostJWTResponse(responseJWE, s.decryptionKey)
	if err != nil {
		out.Error = "couldn't decrypt the response"
		return out
	}
	if parsed.State != id {
		out.Error = "response state doesn't match the request"
		return out
	}
	result, err := a.verifier.VerifyResponse(ctx, verifier.VerifyResponseRequest{
		Query: s.query, Response: parsed, ExpectedNonce: s.nonce,
		IssuerKeys:            verifier.X5CIssuerKeyResolver{Roots: a.cfg.IssuerRoots},
		MdocIssuerKeys:        verifier.X5ChainIssuerKeyResolver{Roots: a.cfg.IssuerRoots},
		MaxKeyBindingAge:      5 * time.Minute,
		ResponseEncryptionKey: s.decryptionKey,
	})
	if err != nil {
		out.Error = "the presentation didn't verify: " + err.Error()
		return out
	}
	if len(result.Credentials) != 1 {
		out.Error = fmt.Sprintf("expected one credential, got %d", len(result.Credentials))
		return out
	}
	vc := result.Credentials[0]
	out.Format = formatOf(vc.CredentialQueryID)
	out.Claims = flatten(vc.CredentialQueryID, vc.Claims)

	if s.mode == ModeICAO {
		out.ICAO = a.checkICAO(out.Claims)
	}
	return out
}

// checkICAO re-runs Passive Authentication over the disclosed raw SOD
// and DG1.
func (a *App) checkICAO(claims map[string]any) *ICAOResult {
	sod, errSOD := rawBytes(claims[credential.ICAOSOD])
	dg1, errDG1 := rawBytes(claims[credential.ICAODG1])
	if errSOD != nil || errDG1 != nil {
		return &ICAOResult{Error: "the credential didn't disclose a usable SOD and DG1"}
	}
	id, err := passport.VerifyDataGroups(sod, dg1, a.cfg.CSCAPool, a.now())
	if err != nil {
		return &ICAOResult{Error: err.Error()}
	}
	return &ICAOResult{Verified: true, Identity: id}
}

// flatten turns a verified credential's claims into one flat map: an
// mdoc's are namespace → element → value, an SD-JWT's already flat.
func flatten(queryID string, claims map[string]any) map[string]any {
	if queryID != mdocQueryID {
		return claims
	}
	out := map[string]any{}
	for _, elements := range claims {
		if m, ok := elements.(map[string]interface{}); ok {
			for k, v := range m {
				out[k] = v
			}
		}
	}
	return out
}

// rawBytes reads a raw data group claim: bytes in an mdoc, base64url
// text in an SD-JWT.
func rawBytes(v any) ([]byte, error) {
	switch x := v.(type) {
	case []byte:
		return x, nil
	case string:
		return base64.RawURLEncoding.DecodeString(x)
	default:
		return nil, errors.New("not disclosed")
	}
}

func formatOf(queryID string) string {
	if queryID == mdocQueryID {
		return "mso_mdoc"
	}
	return "dc+sd-jwt"
}

// responseKeyID reads the response encryption key's kid from a Request
// Object this app just built (its own output, so read without
// re-verifying).
func responseKeyID(requestObject string) (string, error) {
	var claims struct {
		ClientMetadata struct {
			JWKS struct {
				Keys []struct {
					Kid string `json:"kid"`
				} `json:"keys"`
			} `json:"jwks"`
		} `json:"client_metadata"`
	}
	if err := decodeJOSESegment(requestObject, 1, &claims); err != nil || len(claims.ClientMetadata.JWKS.Keys) != 1 {
		return "", fmt.Errorf("verifierapp: request object carries no single response encryption key")
	}
	return claims.ClientMetadata.JWKS.Keys[0].Kid, nil
}

// jweKeyID reads the kid from a compact JWE's protected header.
func jweKeyID(jwe string) (string, error) {
	var header struct {
		Kid string `json:"kid"`
	}
	if err := decodeJOSESegment(jwe, 0, &header); err != nil || header.Kid == "" {
		return "", errors.New("no kid")
	}
	return header.Kid, nil
}

func decodeJOSESegment(compact string, i int, v any) error {
	parts := strings.Split(compact, ".")
	if len(parts) <= i {
		return errors.New("malformed")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[i])
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func mergeFormats(maps ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func randomID() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("verifierapp: random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// newRequestSigningIdentity generates this verifier's request-signing
// key and self-signed certificate. Its hash is the x509_hash client
// identifier; a wallet learns who the verifier is, not whether to
// trust it.
func newRequestSigningIdentity() (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "passport-vdc demo verifier"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("verifierapp: certificate: %w", err)
	}
	return key, cert, nil
}

func writeJSONError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
