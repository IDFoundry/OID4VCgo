package verifierapp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/registration"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// Config configures an App.
type Config struct {
	// VerifierURL is the base of this verifier's endpoints; must be
	// https (the response_uri a wallet posts to).
	VerifierURL string

	// Query, if set, builds a request's DCQL query in place of the
	// scenario's own, from the issuer's vct and its trusted_authorities:
	// to ask for something else of the same credential. A response must
	// still be one credential, or several where the scenario takes
	// several.
	Query func(s Scenario, vct string, trusted dcql.TrustedAuthoritiesQuery) (dcql.Query, error)

	// IssuerVCT is the vct the demo issuer's SD-JWT credentials carry
	// (its issuer URL + "/vct/passport/1").
	IssuerVCT string

	// IssuerCAs are the demo issuer's CA certificates — the trust
	// anchors for credential issuer signatures, in both trust modes.
	// Each request also names them in DCQL trusted_authorities (by
	// Authority Key Identifier), so a wallet offers only credentials
	// they issued.
	IssuerCAs []*x509.Certificate

	// CSCAPool verifies the passport file, for a scenario re-verifying it —
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

	// StateDir, if set, is an existing directory this verifier keeps its
	// request-signing keys and certificates in, so wallets that trust its
	// CA still trust it after a restart. Empty means new CAs each run.
	StateDir string
}

// App is a running passport-vdc verifier.
type App struct {
	cfg    Config
	txs    map[Scenario]*verifier.Transactions // each scenario's relying party has its own identity
	caCert *x509.Certificate
	// registrarCA is the trust anchor of the registrar that registers
	// the trusted scenarios' relying parties.
	registrarCA *x509.Certificate

	issuerRoots   *x509.CertPool
	issuerTrusted dcql.TrustedAuthoritiesQuery // IssuerCAs, by Authority Key Identifier
	now           func() time.Time
	handler       http.Handler

	mu       sync.Mutex
	sessions map[string]*session // by page ID, known only to whoever created the request
	byTx     map[string]string   // verifier transaction ID → page ID
	// outcomes is what each accepted answer established, by verifier
	// transaction ID and then resultKey: Accept runs before its answer
	// commits, so concurrent answers to one request can each be
	// accepted, and only the committed Result says which one counts.
	outcomes map[string]map[string]*Outcome
}

// A session is one "verify a passport credential" page: a presentation
// request offered two ways — cross-device (a QR code) and, for a request
// created in a browser, same-device (a link to the web wallet) — each a
// verifier.Transactions request. The first to complete answers the page;
// the other is then closed. The page's own ID is unrelated to either
// request's (OpenID4VP §14.3.3): only the page that created it knows it.
type session struct {
	scenario     Scenario
	browserToken string // the creating browser's session cookie; "" for CreateRequest
	binding      string // what its requests are bound to: browserToken, or a secret kept here for CreateRequest
	expiresAt    time.Time
	cross, same  channel // same.id is "" without a browser
}

// channel is one of a session's two requests.
type channel struct{ id, link string }

// Outcome is what a verified presentation established.
type Outcome struct {
	Scenario Scenario
	// Decision is what the relying party decides from it.
	Decision Decision
	// Format is the credential format the wallet chose to present.
	Format string
	// Claims are the credential's verified, disclosed claims.
	Claims map[string]any

	// Status is the credential's revocation status, from the Token Status
	// List it references: "valid", or "no status reference" for a
	// credential without one. A revoked, suspended or uncheckable
	// credential isn't accepted at all.
	Status string
	// ICAO is the result of re-verifying the disclosed passport file,
	// for a scenario that requests it.
	ICAO *ICAOResult
	// People are each credential presented, for a scenario that takes
	// several, in the order presented; Format, Claims, Status and ICAO
	// are then the first's.
	People []Person
}

// Decision is what a scenario's relying party decides from a verified
// presentation: whether it goes ahead, and why, in words.
type Decision struct {
	Approved bool
	Text     string
}

// identityOf is the claims that say who a credential is about, in
// either format, without the ones each copy has its own of.
func identityOf(claims map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{
		credential.FamilyName, credential.GivenName, credential.Nationality, credential.SDJWTNationalities,
		credential.BirthDate, "birthdate", credential.DocumentNumber, "age_over_18", credential.SDJWTAgeEqualOrOver,
	} {
		if v, ok := claims[k]; ok {
			out[k] = v
		}
	}
	return out
}

// maxGroup is how many passports a presentation taking several may
// hold: each costs the verifier a status list check.
const maxGroup = 10

// Person is one credential of a presentation taking several.
type Person struct {
	Format string
	Claims map[string]any
	Status string
	ICAO   *ICAOResult // for a scenario re-verifying the passport file
}

// ICAOResult is a re-verification of the disclosed passport file.
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
	ids, err := loadIdentities(cfg.StateDir, time.Now())
	if err != nil {
		return nil, err
	}
	a := &App{
		cfg: cfg, txs: map[Scenario]*verifier.Transactions{}, caCert: ids.ca, registrarCA: ids.registrarCA,
		issuerRoots: issuerRoots, issuerTrusted: issuerTrusted, now: time.Now,
		sessions: map[string]*session{}, byTx: map[string]string{}, outcomes: map[string]map[string]*Outcome{},
	}
	for _, sc := range Scenarios {
		if a.txs[sc], err = a.newTransactions(sc, ids.signers[sc], ids.registrar); err != nil {
			return nil, err
		}
	}
	a.handler = a.routes()
	return a, nil
}

// newTransactions is scenario sc's relying party: a Verifier signing
// its requests as sg, with its own endpoints under /s/<sc>/. A trusted
// one's requests carry its registration, signed by registrar.
func (a *App) newTransactions(sc Scenario, sg signer, registrar signer) (*verifier.Transactions, error) {
	base := a.cfg.VerifierURL + "/s/" + string(sc)
	responseURI, err := fapi.ParseEndpointURL(base + "/response")
	if err != nil {
		return nil, fmt.Errorf("verifierapp: response URI: %w", err)
	}
	rec := haip.RecommendedVerifierConfig()
	cfg := verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: sg.cert, ResponseURI: responseURI,
		SigningAlg: rec.SigningAlg, EncValuesSupported: rec.EncValuesSupported,
		VPFormatsSupported: mergeFormats(verifier.MdocFormatSupport(), verifier.SDJWTVCFormatSupport([]string{"ES256"}, []string{"ES256"})),
	}
	v, err := verifier.New(cfg, verifier.Dependencies{Signer: sg.key, Random: rand.Reader})
	if err != nil {
		return nil, fmt.Errorf("verifierapp: verifier.New: %w", err)
	}
	if info, _ := sc.Info(); info.Trusted {
		token, err := a.register(sc, v.ClientID(), sg.cert.NotAfter, registrar)
		if err != nil {
			return nil, err
		}
		cfg.VerifierInfo = []verifier.VerifierInfo{{Format: registration.Format, Data: token}}
		if v, err = verifier.New(cfg, verifier.Dependencies{Signer: sg.key, Random: rand.Reader}); err != nil {
			return nil, fmt.Errorf("verifierapp: verifier.New: %w", err)
		}
	}
	txs, err := verifier.NewTransactions(v, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{
		RequestURIBase: base + "/request-objects",
		RedirectURI:    base + "/continue",
		Lifetime:       a.cfg.RequestLifetime,
		Verify: verifier.VerifyResponseRequest{
			IssuerKeys:         verifier.X5CIssuerKeyResolver{Roots: a.issuerRoots},
			MdocIssuerKeys:     verifier.X5ChainIssuerKeyResolver{Roots: a.issuerRoots},
			TrustedAuthorities: dcql.AKITrustedAuthoritiesChecker{Roots: a.issuerRoots},
			MaxKeyBindingAge:   5 * time.Minute,
			Now:                func() time.Time { return a.now() },
		},
		Accept: func(ctx context.Context, id string, result verifier.VerifyResponseResult) error {
			return a.accept(ctx, sc, id, result)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("verifierapp: %w", err)
	}
	return txs, nil
}

// registrarID is the demo registrar's identifier, the registrations'
// iss.
const registrarID = "https://registrar.passport-vdc.demo"

// register issues scenario sc's relying party, clientID, its
// registration: its name, its purpose, and the claims its scenario's
// query asks for — or, for one registered as another scenario
// (ScenarioInfo.RegisteredAs), that scenario's.
func (a *App) register(sc Scenario, clientID string, until time.Time, registrar signer) (string, error) {
	info, _ := sc.Info()
	as := sc
	if info.RegisteredAs != "" {
		as = info.RegisteredAs
	}
	asInfo, _ := as.Info()
	q, err := buildQuery(as, a.cfg.IssuerVCT, a.issuerTrusted)
	if err != nil {
		return "", err
	}
	var claims []dcql.Path
	for _, cq := range q.Credentials {
		for _, c := range cq.Claims {
			claims = append(claims, c.Path)
		}
	}
	token, err := registration.Issue(registration.Registration{
		Registrar: registrarID, ClientID: clientID, Name: info.Verifier, Purpose: asInfo.Title,
		Claims: claims, IssuedAt: a.now(), Expires: until,
	}, registrar.key, []*x509.Certificate{registrar.cert})
	if err != nil {
		return "", fmt.Errorf("verifierapp: register %s: %w", sc, err)
	}
	return token, nil
}

// RegistrarCACertificate is the trust anchor of the demo registrar that
// registers the trusted scenarios' relying parties: a wallet configured
// with it (walletflow.Config.RegistrarRoots) shows their registrations,
// and warns when one asks for more.
func (a *App) RegistrarCACertificate() *x509.Certificate { return a.registrarCA }

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

// CreateRequest starts a cross-device presentation request for scenario
// sc and returns its page ID and the openid4vp:// link a wallet answers.
// The ID reads the result (Outcome, the result page) and never appears
// in the link.
func (a *App) CreateRequest(sc Scenario) (id, link string, err error) {
	id, err = a.createSession(context.Background(), sc, "")
	if err != nil {
		return "", "", err
	}
	s, _ := a.session(id)
	return id, s.cross.link, nil
}

// createSession starts a page for scenario sc: a cross-device request, and —
// when browserToken, the creating browser's session cookie, is set — a
// same-device request whose answer Transactions releases only when the
// redirect back arrives in that browser. Without a browser, the page's
// requests are bound to a secret kept here, so a result is released
// only through the page's own ID, never through the request_uri's.
func (a *App) createSession(ctx context.Context, sc Scenario, browserToken string) (string, error) {
	binding := browserToken
	if binding == "" {
		var err error
		if binding, err = randomID(); err != nil {
			return "", err
		}
	}
	txs, ok := a.txs[sc]
	if !ok {
		return "", fmt.Errorf("verifierapp: unknown scenario %q", sc)
	}
	build := buildQuery
	if a.cfg.Query != nil {
		build = a.cfg.Query
	}
	query, err := build(sc, a.cfg.IssuerVCT, a.issuerTrusted)
	if err != nil {
		return "", err
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	s := &session{scenario: sc, browserToken: browserToken, binding: binding}
	cross, err := txs.Begin(ctx, query, binding, false)
	if err != nil {
		return "", err
	}
	s.cross = channel{id: cross.ID, link: cross.Link}
	if browserToken != "" {
		same, err := txs.Begin(ctx, query, binding, true)
		if err != nil {
			return "", err
		}
		s.same = channel{id: same.ID, link: same.Link}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.dropExpired(now)
	s.expiresAt = now.Add(a.lifetime())
	a.sessions[id] = s
	for _, ch := range []channel{s.cross, s.same} {
		if ch.id != "" {
			a.byTx[ch.id] = id
		}
	}
	return id, nil
}

// dropExpired forgets expired pages. Called with a.mu held.
func (a *App) dropExpired(now time.Time) {
	for id, s := range a.sessions {
		if now.After(s.expiresAt) {
			delete(a.sessions, id)
		}
	}
	for tx, id := range a.byTx {
		if _, ok := a.sessions[id]; !ok {
			delete(a.byTx, tx)
			delete(a.outcomes, tx)
		}
	}
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

// pageState is a session's progress, as its page shows it.
type pageState struct {
	outcome   *Outcome // set once one request completed
	awaiting  bool     // same-device: verified, waiting for the redirect back
	closed    bool     // the same-device redirect back arrived in another browser
	lastError string   // why the latest refused answer was refused
}

// state reads s's two requests from Transactions. Once one has
// completed, the other is closed.
func (a *App) state(ctx context.Context, s *session) pageState {
	var st pageState
	for _, ch := range []channel{s.cross, s.same} {
		if ch.id == "" {
			continue
		}
		view, err := a.txs[s.scenario].Lookup(ctx, ch.id, s.binding)
		if err != nil {
			continue
		}
		if view.LastError != "" {
			st.lastError = view.LastError
		}
		switch view.Status {
		case verifier.TransactionDone:
			if view.Result != nil {
				a.mu.Lock()
				st.outcome = a.outcomes[ch.id][resultKey(*view.Result)]
				a.mu.Unlock()
			}
		case verifier.TransactionAwaitingRedirect:
			st.awaiting = true
		case verifier.TransactionClosed:
			st.closed = view.LastError != ""
		}
	}
	if st.outcome != nil {
		st.awaiting, st.closed = false, false
		for _, ch := range []channel{s.cross, s.same} {
			if ch.id != "" {
				_ = a.txs[s.scenario].Close(ctx, ch.id) // the other one; a completed request is left as is
			}
		}
	}
	return st
}

// Outcome returns page id's outcome, once a wallet's presentation has
// verified (and, same-device, come back).
func (a *App) Outcome(id string) (*Outcome, bool) {
	s, ok := a.session(id)
	if !ok {
		return nil, false
	}
	st := a.state(context.Background(), s)
	return st.outcome, st.outcome != nil
}

// LastError returns why the latest refused answer to page id was
// refused, if one was.
func (a *App) LastError(id string) string {
	s, ok := a.session(id)
	if !ok {
		return ""
	}
	return a.state(context.Background(), s).lastError
}

// accept is a scenario's Transactions' Accept: it runs on each answer
// that verified, before its request completes, and may run for an answer
// that then loses to a concurrent one, so what it records is looked up
// by the committed Result (resultKey). It refuses an answer to a page
// whose other request already completed, and one whose credential is
// revoked or suspended; otherwise it records what the answer
// established, and what the scenario decides from it.
func (a *App) accept(ctx context.Context, sc Scenario, txID string, result verifier.VerifyResponseResult) error {
	a.mu.Lock()
	s := a.sessions[a.byTx[txID]]
	a.mu.Unlock()
	if s == nil || s.scenario != sc {
		return errors.New("this request is no longer open")
	}
	info, _ := sc.Info()
	for _, ch := range []channel{s.cross, s.same} {
		if ch.id != "" && ch.id != txID {
			if view, err := a.txs[sc].Lookup(ctx, ch.id, s.binding); err == nil &&
				(view.Status == verifier.TransactionDone || view.Status == verifier.TransactionAwaitingRedirect) {
				return errors.New("this request has already been answered")
			}
		}
	}
	switch n := len(result.Credentials); {
	case n == 0 || n > 1 && !info.Multiple:
		return fmt.Errorf("expected one credential, got %d", n)
	case n > maxGroup:
		return fmt.Errorf("expected at most %d passports, got %d", maxGroup, n)
	}
	out := &Outcome{Scenario: sc}
	seen := map[[sha256.Size]byte]bool{}
	for _, vc := range result.Credentials {
		claims := flatten(vc.CredentialQueryID, vc.Claims)
		sum, err := personKey(claims, info.Evidence)
		if err != nil {
			return err
		}
		if seen[sum] {
			return errors.New("the same passport was presented twice")
		}
		seen[sum] = true
		status, err := a.checkStatus(ctx, vc)
		if err != nil {
			return err
		}
		p := Person{Format: formatOf(vc.CredentialQueryID), Claims: claims, Status: status}
		if info.Evidence {
			p.ICAO = a.checkICAO(claims)
		}
		out.People = append(out.People, p)
	}
	first := out.People[0]
	out.Format, out.Claims, out.Status, out.ICAO = first.Format, first.Claims, first.Status, first.ICAO
	if !info.Multiple {
		out.People = nil
	}
	out.Decision = decide(sc, out)
	a.mu.Lock()
	if a.outcomes[txID] == nil {
		a.outcomes[txID] = map[string]*Outcome{}
	}
	a.outcomes[txID][resultKey(result)] = out
	a.mu.Unlock()
	return nil
}

// personKey identifies whose credential claims is, so one person shown
// twice isn't taken for two: the same credential, or another copy of
// it, discloses the same identity (each copy's own key, dates and status
// entry aside), or the same passport file.
func personKey(claims map[string]any, evidence bool) ([sha256.Size]byte, error) {
	if evidence {
		file, err := rawBytes(claims[credential.PassportFile])
		if err != nil {
			return [sha256.Size]byte{}, errors.New("the credential didn't disclose a usable passport file")
		}
		return sha256.Sum256(file), nil
	}
	raw, err := json.Marshal(identityOf(claims))
	if err != nil {
		return [sha256.Size]byte{}, errors.New("the credential's claims can't be compared")
	}
	return sha256.Sum256(raw), nil
}

// resultKey identifies a verified answer's result, so the outcome shown
// is the one for the answer that committed.
func resultKey(result verifier.VerifyResponseResult) string {
	raw, err := json.Marshal(result.Credentials)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return string(sum[:])
}

// handleContinue is the same-device redirect_uri: the wallet sends the
// browser here with the response_code it was given. Transactions
// releases the result only if this browser presents the session cookie
// of the one that created the request; otherwise it closes the request
// (HAIP 1.0 §5: the redirect back arriving in a different user session).
func (a *App) handleContinue(w http.ResponseWriter, r *http.Request) {
	var token string
	if c, err := r.Cookie(sessionCookie); err == nil {
		token = c.Value
	}
	txs, ok := a.txs[Scenario(r.PathValue("scenario"))]
	if !ok {
		writeHTMLError(w, http.StatusNotFound, "unknown scenario")
		return
	}
	view, err := txs.Redeem(r.Context(), r.URL.Query().Get("response_code"), token)
	switch {
	case errors.Is(err, verifier.ErrWrongBrowser):
		writeHTMLError(w, http.StatusForbidden, "Presentation rejected: the wallet's redirect back arrived in a different browser session than the one that asked.")
		return
	case err != nil:
		writeHTMLError(w, http.StatusBadRequest, "this link is unknown, expired or already used")
		return
	}
	a.mu.Lock()
	id := a.byTx[view.ID]
	a.mu.Unlock()
	http.Redirect(w, r, "/requests/"+id, http.StatusSeeOther) // #nosec G710 -- local path + a server-generated random ID
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
	case errors.Is(err, passport.ErrNotTrusted):
		// gmrtd doesn't say which check failed without its error text,
		// which can hold the MRZ: this covers each.
		return &ICAOResult{Error: "the passport file failed Passive Authentication: its data isn't signed by a recognised issuing country, or doesn't match what was signed"}
	case errors.Is(err, passport.ErrUnreadable):
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
