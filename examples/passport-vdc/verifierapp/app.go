package verifierapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
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

	// IssuerCAs are the demo issuer's CA certificates — the trust
	// anchors for credential issuer signatures, in both trust modes.
	// Each request also names them in DCQL trusted_authorities (by
	// Authority Key Identifier), so a wallet offers only credentials
	// they issued.
	IssuerCAs []*x509.Certificate

	// CSCAPool verifies the passport file in ModeICAO —
	// cms.DefaultMasterList for real passports.
	CSCAPool cms.CertPool

	// RequestLifetime bounds how long a presentation request stays
	// answerable; zero means 10 minutes.
	RequestLifetime time.Duration

	// WebWalletURL, if set, adds an "Open in web wallet" button to the
	// request page, linking to the demo web wallet's /present.
	WebWalletURL string

	// HTTP fetches the Token Status Lists credentials reference, to
	// check they haven't been revoked; it must trust the issuer's TLS
	// certificate. Nil uses http.DefaultClient.
	HTTP *http.Client
}

// App is a running passport-vdc verifier.
type App struct {
	cfg      Config
	verifier *verifier.Verifier
	caCert   *x509.Certificate

	issuerRoots   *x509.CertPool
	issuerTrusted dcql.TrustedAuthoritiesQuery // IssuerCAs, by Authority Key Identifier
	now           func() time.Time
	handler       http.Handler

	mu       sync.Mutex
	sessions map[string]*session   // by request ID, known only to whoever created the request
	byState  map[string]channelRef // OpenID4VP state (also the request_uri path) → channel
	byKeyID  map[string]channelRef // response encryption key ID → channel
	byCode   map[string]string     // same-device response_code → request ID
}

// A request has unrelated random values (OpenID4VP §14.3.3, §13.3): the
// state of each channel, which a wallet sees (in the request_uri and the
// Request Object); its ID, which only the page that created it knows and
// which alone reads the result; and, for a request created in a browser,
// that browser's session cookie, which the same-device redirect back
// must present.
type session struct {
	mode         Mode
	query        dcql.Query
	expiresAt    time.Time
	browserToken string // the creating browser's session cookie; "" for CreateRequest

	crossDevice *channel // answered from another device: no redirect back
	sameDevice  *channel // answered on this device: redirect back, bound to browserToken; nil without one

	awaiting  *Outcome // same-device: verified, released when the redirect back arrives in this browser
	outcome   *Outcome // set once, by the first response that verifies (and, same-device, comes back)
	lastError string   // why the latest rejected response was rejected
	closed    bool     // answered and then rejected: no further answer is accepted
}

// channel is one Authorization Request of a session, with its own state,
// nonce and response encryption key.
type channel struct {
	sameDevice    bool
	state         string
	kid           string
	nonce         string
	requestObject string
	decryptionKey *ecdsa.PrivateKey
	link          string
}

type channelRef struct {
	id         string
	sameDevice bool
}

func (s *session) channel(sameDevice bool) *channel {
	if sameDevice {
		return s.sameDevice
	}
	return s.crossDevice
}

// Outcome is what a verified presentation established.
type Outcome struct {
	Mode Mode
	// Format is the credential format the wallet chose to present.
	Format string
	// Claims are the credential's verified, disclosed claims (ModeIssuer).
	Claims map[string]any

	// Status is the credential's revocation status, from the Token Status
	// List it references: "valid", or "no status reference" for a
	// credential without one. A revoked, suspended or uncheckable
	// credential isn't accepted at all.
	Status string
	// ICAO is the result of re-verifying the disclosed passport file
	// (ModeICAO).
	ICAO *ICAOResult
}

// ICAOResult is a ModeICAO check of the passport file.
type ICAOResult struct {
	Verified bool
	Identity passport.Identity
	// Portrait is the photo from the file's own, country-signed DG2, as
	// JPEG (nil when there's no usable one).
	Portrait []byte
	// ChipAuthenticity is gmrtd's verdict on the file's chip
	// authentication evidence, replayed here.
	ChipAuthenticity string
	// Expired is whether the passport is past its expiry date — shown,
	// not refused: expiry doesn't make the data less authentic.
	Expired bool
	Error   string
}

// New wires an App. Its request-signing key and certificate (the
// x509_hash client identifier) are generated per process.
func New(cfg Config) (*App, error) {
	if cfg.VerifierURL == "" || cfg.IssuerVCT == "" || len(cfg.IssuerCAs) == 0 || cfg.CSCAPool == nil {
		return nil, fmt.Errorf("verifierapp: VerifierURL, IssuerVCT, IssuerCAs and CSCAPool are required")
	}
	issuerRoots := x509.NewCertPool()
	for _, ca := range cfg.IssuerCAs {
		issuerRoots.AddCert(ca)
	}
	issuerTrusted, err := dcql.AKITrustedAuthorities(cfg.IssuerCAs...)
	if err != nil {
		return nil, fmt.Errorf("verifierapp: %w", err)
	}
	responseURI, err := fapi.ParseEndpointURL(cfg.VerifierURL + "/response")
	if err != nil {
		return nil, fmt.Errorf("verifierapp: response URI: %w", err)
	}
	key, cert, caCert, err := newRequestSigningIdentity(time.Now())
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
	a := &App{cfg: cfg, verifier: v, caCert: caCert, issuerRoots: issuerRoots, issuerTrusted: issuerTrusted, now: time.Now, sessions: map[string]*session{}, byState: map[string]channelRef{}, byKeyID: map[string]channelRef{}, byCode: map[string]string{}}
	a.handler = a.routes()
	return a, nil
}

// VerifierCACertificate is the demo verifier CA that issued this
// verifier's request-signing certificate — the trust anchor a wallet
// configures to accept its requests (OpenID4VP §5.9.3).
func (a *App) VerifierCACertificate() *x509.Certificate { return a.caCert }

// ServeHTTP implements http.Handler.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.handler.ServeHTTP(w, r) }

func (a *App) lifetime() time.Duration {
	if a.cfg.RequestLifetime == 0 {
		return 10 * time.Minute
	}
	return a.cfg.RequestLifetime
}

// CreateRequest starts a cross-device presentation request in mode
// and returns its ID and the openid4vp:// link a wallet answers. The ID
// reads the result (Outcome, the result page) and never appears in the
// link.
func (a *App) CreateRequest(mode Mode) (id, link string, err error) {
	id, err = a.createSession(mode, "")
	if err != nil {
		return "", "", err
	}
	s, _ := a.session(id)
	return id, s.crossDevice.link, nil
}

// createSession starts a request in mode: a cross-device channel, and —
// when browserToken, the creating browser's session cookie, is set — a
// same-device channel whose answer is released only when the redirect
// back arrives in that browser.
func (a *App) createSession(mode Mode, browserToken string) (string, error) {
	query, err := buildQuery(mode, a.cfg.IssuerVCT, a.issuerTrusted)
	if err != nil {
		return "", err
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	s := &session{mode: mode, query: query, browserToken: browserToken}
	if s.crossDevice, err = a.newChannel(query, false); err != nil {
		return "", err
	}
	if browserToken != "" {
		if s.sameDevice, err = a.newChannel(query, true); err != nil {
			return "", err
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.dropExpired(now)
	s.expiresAt = now.Add(a.lifetime())
	a.sessions[id] = s
	for _, ch := range []*channel{s.crossDevice, s.sameDevice} {
		if ch != nil {
			a.byState[ch.state] = channelRef{id: id, sameDevice: ch.sameDevice}
			a.byKeyID[ch.kid] = channelRef{id: id, sameDevice: ch.sameDevice}
		}
	}
	return id, nil
}

// newChannel builds one signed Authorization Request for query.
func (a *App) newChannel(query dcql.Query, sameDevice bool) (*channel, error) {
	state, err := randomID()
	if err != nil {
		return nil, err
	}
	built, err := a.verifier.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query, State: state})
	if err != nil {
		return nil, fmt.Errorf("verifierapp: build request: %w", err)
	}
	requestURI := a.cfg.VerifierURL + "/request-objects/" + state
	return &channel{
		sameDevice: sameDevice, state: state, kid: built.ResponseEncryptionKeyID, nonce: built.Nonce,
		requestObject: built.RequestObject, decryptionKey: built.ResponseDecryptionKey,
		link: "openid4vp://?" + url.Values{"client_id": {a.verifier.ClientID()}, "request_uri": {requestURI}}.Encode(),
	}, nil
}

// dropExpired forgets expired requests. Called with a.mu held.
func (a *App) dropExpired(now time.Time) {
	for id, s := range a.sessions {
		if now.After(s.expiresAt) {
			delete(a.sessions, id)
		}
	}
	for _, index := range []map[string]channelRef{a.byState, a.byKeyID} {
		for k, ref := range index {
			if _, ok := a.sessions[ref.id]; !ok {
				delete(index, k)
			}
		}
	}
	for code, id := range a.byCode {
		if _, ok := a.sessions[id]; !ok {
			delete(a.byCode, code)
		}
	}
}

// closeChannels stops s's channels accepting answers. Called with a.mu
// held.
func (a *App) closeChannels(s *session) {
	for _, ch := range []*channel{s.crossDevice, s.sameDevice} {
		if ch != nil {
			delete(a.byState, ch.state)
			delete(a.byKeyID, ch.kid)
		}
	}
}

// Outcome returns request id's outcome, once a wallet's presentation
// has verified.
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

// LastError returns why the latest rejected response to request id was
// rejected, if one was.
func (a *App) LastError(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.sessions[id]; ok {
		return s.lastError
	}
	return ""
}

// handleRequestObject serves a request's signed Request Object at its
// request_uri.
func (a *App) handleRequestObject(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	ref := a.byState[r.PathValue("state")]
	a.mu.Unlock()
	s, ok := a.session(ref.id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	_, _ = w.Write([]byte(s.channel(ref.sameDevice).requestObject))
}

// handleResponse is the response_uri: it routes the encrypted response
// to its request's channel by the JWE's key ID and verifies it.
//
// Anyone can encrypt to the request's public key and copy its state, so
// a response that fails to verify changes nothing but lastError: the
// request stays open for the real wallet. The first response that
// verifies closes the request. From the cross-device channel it is the
// outcome at once; from the same-device channel it is held, and the
// wallet is sent a redirect_uri with a fresh response_code (OpenID4VP
// §8.2, §13.3) — the outcome is released only when that redirect comes
// back in the browser that created the request (handleContinue).
func (a *App) handleResponse(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, "invalid_request", "malformed response")
		return
	}
	responseJWE := r.PostForm.Get("response")
	kid, err := verifier.ResponseKeyID(responseJWE)
	if err != nil {
		writeJSONError(w, "invalid_request", "response is not a JWE with a key ID")
		return
	}
	a.mu.Lock()
	ref := a.byKeyID[kid]
	a.mu.Unlock()
	s, ok := a.session(ref.id)
	if !ok {
		writeJSONError(w, "invalid_request", "no pending request for this response")
		return
	}
	ch := s.channel(ref.sameDevice)

	outcome, err := a.verify(r.Context(), s, ch, responseJWE)
	var code string
	if err == nil && ch.sameDevice {
		if code, err = randomID(); err != nil {
			writeJSONError(w, "server_error", "internal error")
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case s.outcome != nil || s.awaiting != nil || s.closed:
		writeJSONError(w, "invalid_request", "this request has already been answered")
		return
	case err != nil:
		s.lastError = err.Error()
		writeJSONError(w, "invalid_request", err.Error())
		return
	}
	a.closeChannels(s)
	body := map[string]string{}
	if ch.sameDevice {
		s.awaiting = outcome
		a.byCode[code] = ref.id
		body["redirect_uri"] = a.cfg.VerifierURL + "/continue?" + url.Values{"response_code": {code}}.Encode()
	} else {
		s.outcome = outcome
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// handleContinue is the same-device redirect_uri: the wallet sends the
// browser here with the response_code it was given. The held outcome is
// released only if this browser presents the session cookie of the one
// that created the request; otherwise the presentation is rejected
// (HAIP 1.0 §5: the redirect back arriving in a different user session).
func (a *App) handleContinue(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("response_code")
	a.mu.Lock()
	id, ok := a.byCode[code]
	delete(a.byCode, code)
	a.mu.Unlock()
	s, found := a.session(id)
	if !ok || !found {
		writeHTMLError(w, http.StatusBadRequest, "this link is unknown, expired or already used")
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.awaiting == nil {
		writeHTMLError(w, http.StatusBadRequest, "this link is unknown, expired or already used")
		return
	}
	if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.browserToken)) != 1 {
		s.awaiting, s.closed = nil, true
		s.lastError = "the wallet's redirect back arrived in a different browser session than the one that asked"
		writeHTMLError(w, http.StatusForbidden, "Presentation rejected: "+s.lastError+".")
		return
	}
	s.outcome, s.awaiting = s.awaiting, nil
	http.Redirect(w, r, "/requests/"+id, http.StatusSeeOther) // #nosec G710 -- local path + a server-generated random ID
}

// verify checks a response against its request's channel ch.
func (a *App) verify(ctx context.Context, s *session, ch *channel, responseJWE string) (*Outcome, error) {
	out := &Outcome{Mode: s.mode}
	parsed, err := a.verifier.ParseDirectPostJWTResponse(responseJWE, ch.decryptionKey)
	if err != nil {
		return nil, errors.New("couldn't decrypt the response")
	}
	if parsed.State != ch.state {
		return nil, errors.New("response state doesn't match the request")
	}
	result, err := a.verifier.VerifyResponse(ctx, verifier.VerifyResponseRequest{
		Query: s.query, Response: parsed, ExpectedNonce: ch.nonce,
		IssuerKeys:            verifier.X5CIssuerKeyResolver{Roots: a.issuerRoots},
		MdocIssuerKeys:        verifier.X5ChainIssuerKeyResolver{Roots: a.issuerRoots},
		TrustedAuthorities:    dcql.AKITrustedAuthoritiesChecker{Roots: a.issuerRoots},
		MaxKeyBindingAge:      5 * time.Minute,
		ResponseEncryptionKey: ch.decryptionKey,
	})
	if err != nil {
		return nil, fmt.Errorf("the presentation didn't verify: %w", err)
	}
	if len(result.Credentials) != 1 {
		return nil, fmt.Errorf("expected one credential, got %d", len(result.Credentials))
	}
	vc := result.Credentials[0]
	out.Format = formatOf(vc.CredentialQueryID)
	if out.Status, err = a.checkStatus(ctx, vc); err != nil {
		return nil, err
	}
	out.Claims = flatten(vc.CredentialQueryID, vc.Claims)

	if s.mode == ModeICAO {
		out.ICAO = a.checkICAO(out.Claims)
	}
	return out, nil
}

// checkICAO re-verifies the disclosed passport file exactly as the
// issuer did: gmrtd Passive Authentication against the CSCA pool, and
// its document checks. gmrtd's own errors can embed the MRZ, so only
// passport's fixed errors reach the page.
func (a *App) checkICAO(claims map[string]any) *ICAOResult {
	file, err := rawBytes(claims[credential.PassportFile])
	if err != nil {
		return &ICAOResult{Error: "the credential didn't disclose a usable passport file"}
	}
	e, err := passport.Verify(file, a.cfg.CSCAPool, a.now())
	switch {
	case errors.Is(err, passport.ErrNotTrusted), errors.Is(err, passport.ErrUnreadable):
		return &ICAOResult{Error: err.Error()}
	case err != nil:
		return &ICAOResult{Error: "the passport file's data couldn't be used"}
	}
	return &ICAOResult{
		Verified: true, Identity: e.Identity, Portrait: e.Portrait, ChipAuthenticity: e.Checks.ChipAuthenticity,
		Expired: e.Identity.ExpiredAt(a.now()),
	}
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
// key and a certificate for it from a demo verifier CA, whose key is
// then discarded (HAIP 1.0 §5: the certificate signing the request must
// not be self-signed). The certificate's hash is the x509_hash client
// identifier; a wallet trusts it by trusting the CA.
func newRequestSigningIdentity(now time.Time) (key *ecdsa.PrivateKey, cert, caCert *x509.Certificate, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verifierapp: CA key: %w", err)
	}
	caCert, err = democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "passport-vdc demo verifier CA", Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
	}, nil, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verifierapp: %w", err)
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verifierapp: key: %w", err)
	}
	cert, err = democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "passport-vdc demo verifier", Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("verifierapp: %w", err)
	}
	return key, cert, caCert, nil
}

func writeJSONError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
