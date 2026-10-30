package walletflow

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Config configures a Wallet.
type Config struct {
	// ClientID and RedirectURI are the wallet's registration with
	// Authorization Servers: the client_id its Wallet Attestations
	// name, and where the authorization code grant redirects back to.
	// ClientID is REQUIRED to authenticate with a Wallet Attestation,
	// and RedirectURI for the authorization code grant; a wallet
	// receiving credentials only from pre-authorized codes redeemed
	// with no client authentication needs neither. Outside Development,
	// RedirectURI must be a native app's: a private-use URI scheme
	// (com.example.wallet:/callback) or loopback http to 127.0.0.1 or
	// [::1] (RFC 8252 §7.1, §7.3), not an https link, which
	// ResumeIssuance can't complete (see AuthorizationStore). At every
	// assurance level, New refuses a RedirectURI fapigo/client wouldn't
	// take: a private-use scheme is a reverse-order domain name and a
	// single slash, reverse.domain:/path (com.example.wallet:/callback,
	// not myapp:/callback or com.example.wallet://callback), and no
	// redirect URI carries a fragment or credentials.
	ClientID    string
	RedirectURI string

	// IssuerRoots are the trust anchors for issuers: every received
	// credential must be signed by a certificate chaining to one of
	// them, or it's refused — an mdoc only when MdocIssuerRoots and
	// MdocIssuerRootsByDocType don't apply to it. REQUIRED for
	// StartIssuance, unless the wallet receives only mdocs and those
	// are set.
	//
	// Use the issuers' own CAs, never x509.SystemCertPool or a pool
	// built from it: that anchors every public CA, a TLS server's
	// certificate among them. New doesn't refuse one (the verifier's
	// resolvers do under production), and on macOS, iOS and Windows a
	// system pool with certificates appended to it can't be told from
	// any other pool. The same goes for MdocIssuerRoots,
	// MdocIssuerRootsByDocType, IssuerMetadataRoots and RegistrarRoots.
	IssuerRoots *x509.CertPool
	// IssuerLeafPolicy, if set, decides whether a certificate under
	// IssuerRoots may sign credentials
	// (wallet.VerifyIssuedCredentialParams.IssuerLeafPolicy): set it
	// where IssuerRoots also anchor another role, such as Verifiers.
	// It applies to an mdoc too unless MdocIssuerLeafPolicy is set or
	// the mdoc's roots are mdoc-specific.
	IssuerLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error

	// MdocIssuerRoots, if set, are the trust anchors for mdoc document
	// signers (the IACAs, ISO/IEC 18013-5 Annex B) in place of
	// IssuerRoots: a received mdoc ("mso_mdoc") must chain to one of
	// them, and an anchor in IssuerRoots alone, an SD-JWT VC issuer's
	// CA say, can't sign one. Unset, mdocs chain to IssuerRoots.
	MdocIssuerRoots *x509.CertPool
	// MdocIssuerRootsByDocType, if set, are each document type's own
	// IACAs, as verifier.X5ChainIssuerKeyResolver's RootsByDocType: an
	// mdoc of a type it names must chain to that type's anchors, not to
	// MdocIssuerRoots or IssuerRoots, so a PID issuer's IACA can't sign
	// an mDL, say. A type named with a nil pool is refused.
	MdocIssuerRootsByDocType map[string]*x509.CertPool
	// MdocIssuerLeafPolicy, if set, decides whether a certificate under
	// an mdoc's roots may sign mdocs, in place of IssuerLeafPolicy:
	// document signers carry another extended key usage than SD-JWT VC
	// issuers (mdoc.MDLDocumentSignerEKU), so a wallet receiving both
	// sets each its own. Unset, an mdoc under IssuerRoots gets
	// IssuerLeafPolicy, and one under MdocIssuerRoots or
	// MdocIssuerRootsByDocType mdoc.DefaultDocumentSignerPolicy.
	MdocIssuerLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// IssuerRevocation checks a received credential's issuer
	// certificate chain for revocation, under IssuerRoots and the mdoc
	// roots alike (wallet.VerifyIssuedCredentialParams.IssuerRevocation):
	// a credential whose signer, or a CA above it, is revoked is refused
	// on receipt, deferred or refreshed alike, with an error wrapping
	// certrevocation.ErrRevoked. A certrevocation.CRLs fails closed for
	// a CA it has no current list from, so use one only where the
	// issuers' CAs publish CRLs; each role has its own field for that
	// reason. Outside Development, New requires it, and StatusRevocation,
	// whenever IssuerRoots, MdocIssuerRoots or MdocIssuerRootsByDocType
	// is set: certrevocation.NoCheck{} declines. In Development, nil
	// checks no revocation; see certrevocation.
	IssuerRevocation certrevocation.Checker

	// StatusRevocation checks the certificate chain of a status list's
	// signer for revocation in CheckStatus
	// (statuslist.VerifyOptions.Revocation): a list signed under a
	// revoked certificate is refused. An mdoc's list may chain to the
	// Certificate its MSO names, whose CRL is then needed too. Outside
	// Development, New requires it whenever the wallet receives
	// credentials, as IssuerRevocation: any credential may name a status
	// list. certrevocation.NoCheck{} declines; in Development, nil checks
	// no revocation.
	StatusRevocation certrevocation.Checker

	// StatusIssuers are the Status Issuers that may sign a credential
	// issuer's status lists on its behalf (draft-ietf-oauth-status-list):
	// credential issuer (an SD-JWT VC's iss) → the identifiers of its
	// Status Issuers, each recognized by a certificate under IssuerRoots
	// naming it (a uniformResourceIdentifier, or for a "dns:" one a
	// dNSName). CheckStatus otherwise accepts only a status list the
	// credential's issuer signed itself, with the credential's own key
	// or a certificate naming its iss, so another issuer under the same
	// roots can't decide its status. An mdoc's is bound as ISO/IEC
	// 18013-5 §12.3.6 says instead: under the Certificate its MSO's
	// status names, or else the CA that signed its document signer;
	// StatusIssuers, keyed by iss, doesn't apply to it.
	StatusIssuers map[string][]string

	// RequireIssuerName refuses a received SD-JWT VC whose iss its
	// signing certificate doesn't name
	// (wallet.VerifyIssuedCredentialParams.RequireIssuerName). SD-JWT VC
	// doesn't require them to correspond, so it's off by default: set
	// it where IssuerRoots certify several issuers, so none can issue in
	// another's name.
	RequireIssuerName bool

	// AllowForeignIss receives an SD-JWT VC whose iss isn't the
	// Credential Issuer Identifier it was requested from (the offer's
	// credential_issuer). By default one is refused, received, deferred
	// or refreshed (wallet.VerifyIssuedCredentialParams.CredentialIssuer):
	// IssuerRoots may certify several issuers, and an issuer the holder
	// was sent to could otherwise hand over another's credential, issued
	// for the holder's keys, as its own. A credential with no iss names
	// none to check. OpenID4VCI 1.0 §14.4 lets an issued credential name
	// its issuer differently from the Credential Issuer Identifier: set
	// it only for issuers that do, where IssuerRoots certify them alone.
	AllowForeignIss bool

	// IssuerMetadataRoots, IssuerMetadataLeafPolicy,
	// IssuerMetadataRevocation, RequireSignedIssuerMetadata,
	// RequireIssuerMetadataName and MaxIssuerMetadataAge are the
	// Credential Issuer Metadata trust settings of wallet.Config: with
	// IssuerMetadataRoots set, signed metadata (OpenID4VCI §12.2.3, HAIP
	// 1.0 §4.1) is asked for and verified, and RequireSignedIssuerMetadata
	// refuses an issuer without it, before the holder authenticates or
	// enters a transaction code. See wallet.Config for each. Outside
	// Development, New requires IssuerMetadataRevocation with
	// IssuerMetadataRoots: certrevocation.NoCheck{} declines.
	IssuerMetadataRoots         *x509.CertPool
	IssuerMetadataLeafPolicy    func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	IssuerMetadataRevocation    certrevocation.Checker
	RequireSignedIssuerMetadata bool
	RequireIssuerMetadataName   bool
	MaxIssuerMetadataAge        time.Duration

	// IssuanceProfile is the profile issuance follows. The zero value,
	// ProfileOpenID4VCI, follows the issuer's and Authorization Server's
	// metadata; ProfileHAIP also refuses issuers outside HAIP 1.0.
	IssuanceProfile IssuanceProfile

	// VerifierTrust decides which Verifiers the wallet answers
	// (OpenID4VP 1.0 §5.9.3). REQUIRED for StartPresentation, and for a
	// signed request to StartDCAPIPresentation. A
	// wallet.X5CVerifierRoots checks its Verifiers' certificates for
	// revocation with its own Revocation, which New requires outside
	// Development: certrevocation.NoCheck{} declines.
	VerifierTrust wallet.VerifierTrust

	// RegistrarRoots, if set, are the registrars whose registrations of
	// Verifiers the wallet checks (the registration package): a
	// request's registration, from its verifier_info, is reported with
	// what the request asks beyond it (Presentation.Registration).
	// Unset, registrations are ignored. They must anchor only
	// registrars: any end-entity certificate under them can register a
	// Verifier, so roots shared with Verifiers or Issuers would let them
	// register themselves. A registration signed with the Verifier's own
	// key is never accepted.
	RegistrarRoots *x509.CertPool
	// RegistrarLeafPolicy, if set, decides whether a certificate under
	// RegistrarRoots may sign registrations: an extended key usage or
	// certificate policy the ecosystem defines for registrars, say.
	// Unset, registration.DefaultRegistrarLeafPolicy refuses the
	// certificates whose key usage clearly denotes another role.
	RegistrarLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// RegistrarRevocation checks a registrar's certificate chain for
	// revocation (registration.Registrars.Revocation): a registration
	// signed under a revoked certificate isn't verified. Outside
	// Development, New requires it with RegistrarRoots:
	// certrevocation.NoCheck{} declines. In Development, nil checks no
	// revocation.
	RegistrarRevocation certrevocation.Checker

	// MdocReaderRoots, if set, are the mdoc readers the wallet
	// recognizes when one signs an org-iso-mdoc request
	// (MdocPresentation.Reader) or an in-person one
	// (ProximityPresentation's reader). An unsigned or unrecognized
	// request is still answered if the holder agrees, shown by its
	// origin or as an unknown reader — unless RequireTrustedMdocReader.
	MdocReaderRoots *x509.CertPool
	// MdocReaderLeafPolicy, if set, decides whether a certificate under
	// MdocReaderRoots is a reader's: mdocdcapi.RequireReaderAuthenticationEKU
	// requires the ISO/IEC 18013-5 reader authentication extended key
	// usage, so a certificate issued under the same roots for another
	// role isn't taken for a reader.
	MdocReaderLeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// MdocReaderRevocation checks a reader's certificate chain for
	// revocation, for org-iso-mdoc and in-person requests alike: a
	// reader whose certificate is revoked isn't recognized, so it's
	// shown as untrusted, or refused under RequireTrustedMdocReader.
	// Outside Development, New requires it with MdocReaderRoots:
	// certrevocation.NoCheck{} declines. In Development, nil checks no
	// revocation.
	MdocReaderRevocation certrevocation.Checker
	// RequireTrustedMdocReader refuses an org-iso-mdoc or in-person
	// request no reader under MdocReaderRoots signed, and nothing is
	// shown to the holder: StartMdocPresentation returns an error
	// wrapping ErrUntrustedVerifier, and an in-person session ends with
	// a ProximityEvent whose Err wraps it, sending the reader a
	// termination. It needs MdocReaderRoots.
	RequireTrustedMdocReader bool
	// ProximityDeviceAuth is how an in-person response authenticates the
	// mdoc (ISO/IEC 18013-5 §9.1.3). The zero value,
	// ProximityDeviceSignature, signs with the holder key.
	ProximityDeviceAuth ProximityDeviceAuth

	// RequireSignedDCAPIRequests refuses an unsigned OpenID4VP request
	// over the Digital Credentials API (StartDCAPIPresentation) with an
	// error wrapping ErrUntrustedVerifier, before the holder sees it: its
	// only identity is the origin the platform reports, which
	// VerifierTrust can't judge. HAIP 1.0 §5.2 requires a Wallet to
	// support unsigned requests, so set it only where every Verifier must
	// be one VerifierTrust accepts.
	RequireSignedDCAPIRequests bool

	// Locales are the holder's preferred languages (BCP 47 tags, most
	// preferred first), for the issuer's display metadata: sent as
	// Accept-Language when fetching it (OpenID4VCI 1.0 §12.2.2), and
	// used to pick among its entries. None means the issuer's entry
	// without a locale, else its first.
	Locales []string

	// RequestRefresh asks the Authorization Server, in the authorization
	// code flow, for a refresh token (the offline_access scope), so
	// Wallet.RefreshCredential can later replace a credential's copies
	// without the holder (OpenID4VCI 1.0 §13.5). The server must allow
	// the wallet that scope, or the authorization fails with
	// invalid_scope. In the pre-authorized code flow there's no scope to
	// ask with: a refresh token the server issues anyway is kept. The
	// refresh token and the wallet instance key are then kept in
	// Dependencies.Grants; without RequestRefresh, a refresh token is
	// discarded.
	RequestRefresh bool

	// CopyPolicy decides which copy of a credential a presentation uses
	// (OpenID4VCI 1.0: "a unique Credential per presentation or per
	// Verifier"). The zero value is CopyPerPresentation.
	CopyPolicy CopyPolicy

	// BatchSize is how many copies of each credential to request when
	// the issuer offers batch issuance, each bound to its own key, so
	// each presentation can use one no Verifier has seen. It's capped at
	// the issuer's batch_size. Zero means DefaultBatchSize; 1 requests
	// one copy.
	BatchSize int

	// Development relaxes what production requires, for a wallet
	// talking to services on this machine. Never set it in a wallet
	// that holders use, nor just to use memory stores: it also drops
	// the network protections below. It:
	//   - lets issuers, Authorization Servers, Verifiers and status
	//     lists be on loopback addresses, over http there too;
	//   - permits wallet.NoVerifierTrust as VerifierTrust;
	//   - makes requests through an ordinary HTTP client, which reaches
	//     private networks, instead of the hardened one;
	//   - skips the checks New makes at production assurance: Durable
	//     Authorizations (and Grants, with RequestRefresh), Keys
	//     declaring durable custody, Random crypto/rand, roles' pools
	//     sharing no anchor (or leaf policies), a revocation Checker for
	//     each role in use — and fapigo/client's own production checks.
	Development bool

	// TLSPins, if set, pins hosts' certificates (see TLSPins) on the
	// HTTP client New builds when Dependencies.HTTP is nil, in
	// Development too. With Dependencies.HTTP set, New refuses them:
	// set TLSPins.VerifyConnection on that client's TLS configuration
	// instead.
	TLSPins TLSPins
}

// Dependencies are what the app supplies.
type Dependencies struct {
	// Keys holds the wallet's keys. REQUIRED. Production assurance
	// checks only that it declares durable custody
	// (keys.KeyCustodyAssurance) — it can't check where the keys are.
	// A wallet's holder keys belong in secure hardware that won't
	// export them (the Secure Enclave, StrongBox), needing the holder's
	// presence to present; that's the KeyStore's to provide.
	Keys        KeyStore
	Credentials CredentialStore // REQUIRED
	// Provider attests the wallet (Wallet Attestations) and its keys
	// (Key Attestations), for issuers that require them: HAIP 1.0's,
	// and any whose Authorization Server takes only a Wallet Attestation
	// or that sets key_attestations_required. nil means the wallet gives
	// neither, and receives credentials only from issuers that need
	// neither (OpenID4VCI 1.0 allows both to be left out). REQUIRED
	// under ProfileHAIP.
	Provider WalletProvider
	// Deferred keeps pending deferred credentials, so they can be polled
	// after a restart. nil means a MemoryDeferredStore.
	Deferred DeferredStore
	// Authorizations keeps the authorizations in progress, so the
	// redirect can complete one after a restart (ResumeIssuance). nil
	// means a MemoryAuthorizationStore. Receiving credentials at
	// production assurance (Config.Development false) needs a Durable
	// one, Keys that declare durable custody (keys.KeyCustodyAssurance),
	// and Random left nil or crypto/rand.Reader.
	Authorizations AuthorizationStore
	// Grants keeps refresh grants (Config.RequestRefresh). nil means a
	// MemoryGrantStore. Receiving credentials at production assurance
	// with RequestRefresh set needs a Durable one.
	Grants GrantStore

	// HTTP makes every request. nil means a client with a 10 s timeout
	// that, outside Development, is fapihttp's hardened one: it dials
	// only public addresses and follows no redirect. One set here should
	// be as careful: issuers' and Verifiers' endpoints come from offers
	// and requests anyone can make. One without a Timeout is used
	// through a copy with the 10 s one, its Transport and CheckRedirect
	// kept, so a server that never answers can't hold a request until
	// its context ends.
	HTTP *http.Client
	// Clock returns the current time. nil means time.Now, the only
	// clock receiving credentials accepts outside Development: every
	// expiry the issuance's OAuth client enforces rests on it.
	Clock func() time.Time
	// Random is the source of identifiers and protocol randomness. nil
	// means crypto/rand.
	Random io.Reader
}

// Wallet is a holder's wallet. Its methods are safe for concurrent use;
// each session they start is used by one goroutine at a time.
type Wallet struct {
	cfg  Config
	deps Dependencies
	core *wallet.Wallet

	mu       sync.Mutex
	deferred map[string]*Deferred // the pending ones handed out, by ID
	// settled are the IDs of the deferred credentials settled since the
	// wallet was created: Wallet.Deferred skips one a listing that raced
	// its settling still returned.
	settled map[string]bool
	// liveKeys are the instance and DPoP keys open issuances hold, by
	// ID: how many hold each. Two issuances can hold one key (a resumed
	// authorization and the issuance that began it, or two resumes of
	// one redirect), and the first to close mustn't delete it.
	liveKeys map[string]int
	// systemClock is whether deps.Clock is the system's (Dependencies.Clock
	// was nil), which fapigo/client requires under production assurance.
	systemClock bool
	// resuming are the authorizations ResumeIssuance is completing, by
	// state: a second resume of one redirect waits for none.
	resuming map[string]bool
	// openGrants are the refresh grants open issuances hold, by ID: in
	// use until the issuance closes, however many credentials are stored
	// yet.
	openGrants map[string]bool
	// grantMu serializes refreshes per refresh grant (grantLocks, by
	// grant ID), held across the refresh's requests, so one here waits
	// for another rather than find the grant claimed
	// (ErrRefreshInProgress), as one in another Wallet sharing the
	// GrantStore does. The stores' own atomic operations — consuming an
	// authorization, updating a credential or a grant — keep every other
	// read-modify-write safe across Wallets.
	grantMu    sync.Mutex
	grantLocks map[string]*sync.Mutex
}

// CopyPolicy is which copy of a credential a presentation uses.
type CopyPolicy int

const (
	// CopyPerPresentation presents a copy no Verifier has seen, every
	// time: not even the same Verifier can link two presentations by the
	// credential. Copies run out fastest. It's the default.
	CopyPerPresentation CopyPolicy = iota
	// CopyPerVerifier presents a Verifier the copy it has seen before, if
	// any, else one no Verifier has seen: Verifiers can't link
	// presentations to each other, but one Verifier can recognise a
	// returning holder. Copies last as long as there are new Verifiers.
	CopyPerVerifier
)

// DefaultBatchSize is how many copies of a credential a wallet requests
// when Config.BatchSize is zero and the issuer offers batch issuance.
const DefaultBatchSize = 5

const (
	httpTimeout      = 10 * time.Second
	maxResponseBytes = 1 << 20
)

// New returns a Wallet. Make one per set of stores and share it: a
// Wallet serializes its own use of them (choosing the copies a
// presentation uses, consuming an authorization, refreshing a grant), so
// two over the same Keys and Credentials don't coordinate, and could
// present the same copy twice, linking the presentations, or redeem the
// same refresh token twice, which an authorization server rotating
// refresh tokens answers by revoking the grant.
func New(cfg Config, deps Dependencies) (*Wallet, error) {
	if deps.Keys == nil || deps.Credentials == nil {
		return nil, errors.New("walletflow: Dependencies.Keys and Credentials are required")
	}
	if cfg.RequireTrustedMdocReader && cfg.MdocReaderRoots == nil {
		return nil, errors.New("walletflow: Config.RequireTrustedMdocReader needs MdocReaderRoots")
	}
	if err := cfg.validateChoices(); err != nil {
		return nil, err
	}
	if err := cfg.checkRedirectURIForm(); err != nil {
		return nil, err
	}
	if err := cfg.validateRevocation(); err != nil {
		return nil, err
	}
	if !cfg.Development {
		if err := cfg.checkRevocationChosen(); err != nil {
			return nil, err
		}
		if err := checkRoleSeparation(cfg); err != nil {
			return nil, err
		}
	}
	if err := cfg.TLSPins.Validate(); err != nil {
		return nil, err
	}
	systemClock := deps.Clock == nil
	deps, err := withDefaultDependencies(cfg, deps)
	if err != nil {
		return nil, err
	}
	core, err := wallet.New(wallet.Config{
		Assurance: cfg.assurance(), ProofSigningAlg: oid4vci.ES256, VerifierTrust: cfg.VerifierTrust,
		RequireSignedDCAPIRequests: cfg.RequireSignedDCAPIRequests,
		IssuerMetadataRoots:        cfg.IssuerMetadataRoots, IssuerMetadataLeafPolicy: cfg.IssuerMetadataLeafPolicy,
		IssuerMetadataRevocation:    cfg.IssuerMetadataRevocation,
		RequireSignedIssuerMetadata: cfg.RequireSignedIssuerMetadata,
		RequireIssuerMetadataName:   cfg.RequireIssuerMetadataName, MaxIssuerMetadataAge: cfg.MaxIssuerMetadataAge,
		Locales: cfg.Locales,
		Fetch: fapihttp.Config{
			MaxResponseBytes: maxResponseBytes, RequestTimeout: httpTimeout, MaxRedirects: 2,
			AllowLoopbackHosts: cfg.Development,
		},
	}, wallet.Dependencies{HTTP: deps.HTTP, Clock: wallet.ClockFunc(deps.Clock), Random: deps.Random})
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	w := &Wallet{
		cfg: cfg, deps: deps, core: core, deferred: map[string]*Deferred{}, settled: map[string]bool{}, liveKeys: map[string]int{}, resuming: map[string]bool{},
		openGrants: map[string]bool{}, grantLocks: map[string]*sync.Mutex{}, systemClock: systemClock,
	}
	if err := w.checkReceivingAtNew(); err != nil {
		return nil, err
	}
	return w, nil
}

// withDefaultDependencies is deps with the wallet's own HTTP client,
// pinned to cfg.TLSPins, and in-memory stores and the system clock and
// randomness for those deps leaves nil, and a caller's HTTP client
// without a Timeout as a copy with httpTimeout. It refuses TLSPins
// alongside a caller's HTTP client, which they wouldn't apply to.
func withDefaultDependencies(cfg Config, deps Dependencies) (Dependencies, error) {
	switch {
	case deps.HTTP == nil:
		client, err := defaultHTTPClient(cfg.Development, cfg.TLSPins)
		if err != nil {
			return deps, err
		}
		deps.HTTP = client
	case len(cfg.TLSPins) > 0:
		return deps, errors.New("walletflow: Config.TLSPins applies to the wallet's own HTTP client, not Dependencies.HTTP: set TLSPins.VerifyConnection on that client's TLS configuration instead")
	case deps.HTTP.Timeout <= 0:
		// The direct_post responses and refusals, and fapigo/client's
		// token and Credential Requests, go through this client
		// directly: without a Timeout, a stalled server holds them
		// until ctx ends.
		timed := *deps.HTTP
		timed.Timeout = httpTimeout
		deps.HTTP = &timed
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	if deps.Random == nil {
		deps.Random = rand.Reader
	}
	if deps.Deferred == nil {
		deps.Deferred = NewMemoryDeferredStore()
	}
	if deps.Authorizations == nil {
		deps.Authorizations = NewMemoryAuthorizationStore()
	}
	if deps.Grants == nil {
		deps.Grants = NewMemoryGrantStore()
	}
	return deps, nil
}

// checkReceivingAtNew checks what receiving credentials needs in
// production now rather than when a holder first tries to receive one:
// checkProductionReceiving's checks, and a Durable Authorizations store
// when issuance redirects.
func (w *Wallet) checkReceivingAtNew() error {
	if w.cfg.Development || !w.cfg.receivesCredentials() {
		return nil
	}
	if err := w.checkProductionReceiving(); err != nil {
		return err
	}
	if w.cfg.RedirectURI != "" && !w.deps.Authorizations.Durable() {
		return errors.New("walletflow: receiving credentials in production needs a Durable Dependencies.Authorizations, so an authorization survives the app being suspended")
	}
	if w.cfg.RedirectURI != "" && !nativeRedirectURI(w.cfg.RedirectURI) {
		return errors.New("walletflow: in production, Config.RedirectURI must be a private-use URI scheme, such as com.example.wallet:/callback, or loopback http to 127.0.0.1 or [::1] (RFC 8252 §7.1, §7.3): ResumeIssuance can't complete an authorization that redirects anywhere else once the app is relaunched")
	}
	return nil
}

// checkRedirectURIForm refuses, at every assurance level, a
// Config.RedirectURI fapigo/client wouldn't build an issuance's client
// with: New would otherwise take it, and every issuance that
// authenticates would fail once the Wallet Provider had been asked for
// an attestation. It's client.Config's own redirect_uri check:
// fapi.ParseRedirectURL admitting loopback http and a private-use
// scheme, which must be a reverse-order domain name followed by a single
// slash and the path, com.example.wallet:/callback (RFC 8252 §7.1) —
// not myapp:/callback, com.example.wallet://callback or
// com.example.wallet:callback — with no fragment or credentials; and,
// under production assurance, a loopback one naming the IP literal
// 127.0.0.1 or [::1] (§8.3).
func (c Config) checkRedirectURIForm() error {
	if c.RedirectURI == "" {
		return nil
	}
	if _, err := fapi.ParseRedirectURL(c.RedirectURI, fapi.AllowLoopbackHTTP(), fapi.AllowPrivateUseScheme()); err != nil {
		return fmt.Errorf("walletflow: Config.RedirectURI must be a private-use URI scheme in reverse.domain:/path form, such as com.example.wallet:/callback, or loopback http, with no fragment or credentials (RFC 8252 §7.1, §7.3): %w", err)
	}
	if u, err := url.Parse(c.RedirectURI); err == nil && !c.Development && u.Scheme == "http" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return errors.New("walletflow: outside Development, a loopback Config.RedirectURI names the IP literal 127.0.0.1 or [::1], not a host name (RFC 8252 §8.3)")
	}
	return nil
}

// nativeRedirectURI reports whether uri is one only a native app
// receives, the only kind fapigo/client lets a resumed issuance complete
// under production assurance (client.CallbackBindingDeviceLocalStore):
// loopback http to an IP literal, or a private-use URI scheme.
func nativeRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	switch u.Scheme {
	case "":
		return false
	case "https":
		return false
	case "http":
		return u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	}
	return true
}

// validateChoices refuses a Config field set to a value it has no
// meaning for, which would otherwise act as its default: an
// IssuanceProfile(9) as the less strict ProfileOpenID4VCI, say.
func (c Config) validateChoices() error {
	switch {
	case c.IssuanceProfile != ProfileOpenID4VCI && c.IssuanceProfile != ProfileHAIP:
		return fmt.Errorf("walletflow: Config.IssuanceProfile %d isn't a profile", c.IssuanceProfile)
	case c.CopyPolicy != CopyPerPresentation && c.CopyPolicy != CopyPerVerifier:
		return fmt.Errorf("walletflow: Config.CopyPolicy %d isn't a policy", c.CopyPolicy)
	case c.BatchSize < 0:
		return fmt.Errorf("walletflow: Config.BatchSize %d is negative", c.BatchSize)
	}
	return nil
}

// validateRevocation refuses a role's revocation Checker that reports
// itself incomplete (certrevocation.CRLs.Validate), so New refuses it
// rather than every credential or request afterwards. VerifierTrust's
// is wallet.New's to check.
func (c Config) validateRevocation() error {
	for _, r := range []struct {
		name    string
		checker certrevocation.Checker
	}{
		{"IssuerRevocation", c.IssuerRevocation},
		{"StatusRevocation", c.StatusRevocation},
		{"IssuerMetadataRevocation", c.IssuerMetadataRevocation},
		{"RegistrarRevocation", c.RegistrarRevocation},
		{"MdocReaderRevocation", c.MdocReaderRevocation},
	} {
		if err := certchain.ValidateRevocation(r.checker); err != nil {
			return fmt.Errorf("walletflow: Config.%s: %w", r.name, err)
		}
	}
	return nil
}

// checkRevocationChosen refuses, in production, a trust role that's in
// use without a revocation Checker, so a role's certificates go
// unchecked only where the configuration says so with
// certrevocation.NoCheck{}, as verifier's and issuer's production
// configurations must: each role whose roots are set needs its own
// Checker. Receiving credentials needs StatusRevocation as well as
// IssuerRevocation, since any credential received may name a status
// list, signed under the same roots, that CheckStatus fetches.
func (c Config) checkRevocationChosen() error {
	const issuerRoots = "IssuerRoots, MdocIssuerRoots or MdocIssuerRootsByDocType"
	receives := c.receivesCredentials()
	verifier, hasVerifier := x5cVerifierRoots(c.VerifierTrust)
	for _, r := range []struct {
		inUse   bool
		field   string
		roots   string
		checker certrevocation.Checker
	}{
		{receives, "IssuerRevocation", issuerRoots, c.IssuerRevocation},
		{receives, "StatusRevocation", issuerRoots, c.StatusRevocation},
		{c.IssuerMetadataRoots != nil, "IssuerMetadataRevocation", "IssuerMetadataRoots", c.IssuerMetadataRevocation},
		{hasVerifier, "VerifierTrust's wallet.X5CVerifierRoots.Revocation", "VerifierTrust", verifier.Revocation},
		{c.RegistrarRoots != nil, "RegistrarRevocation", "RegistrarRoots", c.RegistrarRevocation},
		{c.MdocReaderRoots != nil, "MdocReaderRevocation", "MdocReaderRoots", c.MdocReaderRevocation},
	} {
		if r.inUse && r.checker == nil {
			return fmt.Errorf("walletflow: Config.%s is required outside Development when Config.%s is set: %s", r.field, r.roots, certchain.RevocationChoices)
		}
	}
	return nil
}

// checkRoleSeparation refuses, in production, two roles whose
// certificate pools may share an anchor unless both narrow their
// certificates by a leaf policy (an extended key usage, say): otherwise
// a Verifier's certificate under the shared anchor could sign
// credentials the wallet accepts or an issuer's metadata, an issuer's
// pass for a trusted Verifier or mdoc reader, or a Verifier register
// itself. mayShareAnchor says what it can see of a pool.
//
// The credential issuers' pools, IssuerRoots and the mdoc ones, are
// one role: an ecosystem's CA may certify both its SD-JWT VC issuers
// and its document signers, and what tells those apart is their leaf
// policies, not their anchors.
func checkRoleSeparation(c Config) error {
	roles := []trustRole{
		{"IssuerRoots", c.IssuerRoots, c.IssuerLeafPolicy != nil, roleIssuer},
		{"MdocIssuerRoots", c.MdocIssuerRoots, c.MdocIssuerLeafPolicy != nil, roleIssuer},
		{"IssuerMetadataRoots", c.IssuerMetadataRoots, c.IssuerMetadataLeafPolicy != nil, ""},
		{"RegistrarRoots", c.RegistrarRoots, c.RegistrarLeafPolicy != nil, ""},
		{"MdocReaderRoots", c.MdocReaderRoots, c.MdocReaderLeafPolicy != nil, ""},
	}
	for _, docType := range slices.Sorted(maps.Keys(c.MdocIssuerRootsByDocType)) {
		roles = append(roles, trustRole{fmt.Sprintf("MdocIssuerRootsByDocType[%q]", docType), c.MdocIssuerRootsByDocType[docType], c.MdocIssuerLeafPolicy != nil, roleIssuer})
	}
	if r, ok := verifierTrustRole(c.VerifierTrust); ok {
		roles = append(roles, r)
	}
	for i, a := range roles {
		for _, b := range roles[i+1:] {
			if a.family != "" && a.family == b.family {
				continue
			}
			if err := separated(a, b); err != nil {
				return err
			}
		}
	}
	return nil
}

// roleIssuer is the family of the credential issuers' pools.
const roleIssuer = "issuer"

// trustRole is one of the certificate pools checkRoleSeparation
// compares, whether a leaf policy tells its certificates apart, and
// the family of roles, if any, whose pools may share anchors.
type trustRole struct {
	name      string
	pool      *x509.CertPool
	hasPolicy bool
	family    string
}

// verifierTrustRole is VerifierTrust's pool, by value or by pointer;
// false for a VerifierTrust without one.
func verifierTrustRole(t wallet.VerifierTrust) (trustRole, bool) {
	v, ok := x5cVerifierRoots(t)
	if !ok {
		return trustRole{}, false
	}
	return trustRole{"VerifierTrust", v.Roots, v.LeafPolicy != nil, ""}, true
}

// x5cVerifierRoots is t as a wallet.X5CVerifierRoots, by value or by
// pointer; false for any other VerifierTrust, or a nil pointer.
func x5cVerifierRoots(t wallet.VerifierTrust) (wallet.X5CVerifierRoots, bool) {
	switch v := t.(type) {
	case wallet.X5CVerifierRoots:
		return v, true
	case *wallet.X5CVerifierRoots:
		if v != nil {
			return *v, true
		}
	}
	return wallet.X5CVerifierRoots{}, false
}

// separated refuses a's and b's pools when they may share an anchor,
// unless both have a leaf policy.
func separated(a, b trustRole) error {
	if !mayShareAnchor(a.pool, b.pool) {
		return nil
	}
	for _, r := range []trustRole{a, b} {
		if !r.hasPolicy {
			return fmt.Errorf("walletflow: %s and %s may share a trust anchor: give %s a leaf policy (an extended key usage) to tell its certificates apart, or use pools with no certificate subject in common", a.name, b.name, r.name)
		}
	}
	return nil
}

// mayShareAnchor reports whether pools a and b may vouch for the same
// certificates. A CertPool lists only its certificates' subjects, so
// they may when:
//   - they're the same pool;
//   - they hold certificates with the same subject: the same anchor, a
//     reissue of it, or another CA that a certificate naming that
//     subject as its issuer may chain to;
//   - either is a system pool whose roots the platform keeps
//     (x509.SystemCertPool on macOS, iOS and Windows) and doesn't list:
//     it may hold any anchor.
//
// An intermediate or cross-certificate in one pool that an anchor of
// the other certified under another subject isn't seen: give a role
// whose pool holds one a leaf policy. The mobile façade, which has the
// certificates, also catches those.
func mayShareAnchor(a, b *x509.CertPool) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Equal(b) || opaqueSystemPool(a) || opaqueSystemPool(b) {
		return true
	}
	//nolint:staticcheck // SA1019: deprecated only for a system pool's own roots, which opaqueSystemPool covers
	as, bs := a.Subjects(), b.Subjects()
	subjects := make(map[string]bool, len(as))
	for _, s := range as {
		subjects[string(s)] = true
	}
	for _, s := range bs {
		if subjects[string(s)] {
			return true
		}
	}
	return false
}

// opaqueSystemPool reports whether p holds roots it doesn't list: it
// lists no subjects yet isn't an empty pool, as x509.SystemCertPool's
// is where the platform verifies against its own roots.
func opaqueSystemPool(p *x509.CertPool) bool {
	//nolint:staticcheck // SA1019: deprecated for exactly the pool this detects
	return len(p.Subjects()) == 0 && !p.Equal(x509.NewCertPool())
}

func (c Config) assurance() wallet.AssuranceLevel {
	if c.Development {
		return wallet.AssuranceDevelopment
	}
	return wallet.AssuranceProduction
}

func (c Config) clientAssurance() client.AssuranceLevel {
	if c.Development {
		return client.AssuranceDevelopment
	}
	return client.AssuranceProduction
}

// Credentials returns every credential the wallet holds.
func (w *Wallet) Credentials(ctx context.Context) ([]StoredCredential, error) {
	creds, err := w.deps.Credentials.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list credentials: %w", err)
	}
	return creds, nil
}

// DeleteCredential deletes the credential id names, and every copy's
// holder key. Once no other credential uses its refresh grant, the
// refresh token is revoked at the Authorization Server (RFC 7009), best
// effort and only when it has a revocation endpoint, so the issuer's
// standing grant ends with it; then the grant and its instance key are
// deleted.
func (w *Wallet) DeleteCredential(ctx context.Context, id string) error {
	c, err := w.deleteCredential(ctx, id)
	if err != nil {
		return err
	}
	if err := w.releaseUnusedGrant(ctx, c.GrantID, c.ConfigurationID); err != nil {
		return fmt.Errorf("walletflow: delete credential's refresh grant: %w", err)
	}
	return nil
}

// deleteCredential deletes the credential id names and its copies'
// keys, and returns it. A copy a refresh in another Wallet sharing the
// store gave it between the two leaves its key behind, for a key sweep
// (KeysInUse).
func (w *Wallet) deleteCredential(ctx context.Context, id string) (StoredCredential, error) {
	c, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: delete credential: %w", err)
	}
	if err := w.deps.Credentials.Delete(ctx, id); err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: delete credential: %w", err)
	}
	for _, cp := range c.AllCopies() {
		if err := w.deps.Keys.DeleteKey(ctx, cp.HolderKeyID); err != nil {
			return StoredCredential{}, fmt.Errorf("walletflow: delete credential's holder key: %w", err)
		}
	}
	return c, nil
}

// receivesCredentials reports whether c trusts any credential issuer.
func (c Config) receivesCredentials() bool {
	return c.IssuerRoots != nil || c.MdocIssuerRoots != nil || len(c.MdocIssuerRootsByDocType) > 0
}

// issuerTrust is the trust anchors and leaf policy a received
// credential of format, and for an mdoc docType, is checked against:
// for an mdoc, MdocIssuerRootsByDocType's for a type it names, else
// MdocIssuerRoots, else IssuerRoots, with MdocIssuerLeafPolicy, else
// IssuerLeafPolicy under IssuerRoots alone. A nil pool is refused by
// wallet.VerifyIssuedCredential, as a nil policy means
// mdoc.DefaultDocumentSignerPolicy there.
func (c Config) issuerTrust(format, docType string) (*x509.CertPool, func(*x509.Certificate, [][]*x509.Certificate) error) {
	if format != mdoc.CredentialFormat {
		return c.IssuerRoots, c.IssuerLeafPolicy
	}
	roots, policy := c.IssuerRoots, c.IssuerLeafPolicy
	if byType, ok := c.MdocIssuerRootsByDocType[docType]; ok {
		roots, policy = byType, nil
	} else if c.MdocIssuerRoots != nil {
		roots, policy = c.MdocIssuerRoots, nil
	}
	if c.MdocIssuerLeafPolicy != nil {
		policy = c.MdocIssuerLeafPolicy
	}
	return roots, policy
}

// checkIssuance reports what StartIssuance needs that w lacks, whatever
// the offer: what the grant an offer has needs is checked once it's
// known (checkAuthorizationCode, chooseClientAuth).
func (w *Wallet) checkIssuance() error {
	switch {
	case !w.cfg.receivesCredentials():
		return fmt.Errorf("walletflow: Config.IssuerRoots is required to receive credentials: %w", ErrNotConfigured)
	case w.cfg.IssuanceProfile == ProfileHAIP && (w.deps.Provider == nil || w.cfg.ClientID == ""):
		return fmt.Errorf("walletflow: Dependencies.Provider and Config.ClientID are required to receive credentials under ProfileHAIP: %w", ErrNotConfigured)
	}
	if w.cfg.Development {
		return nil
	}
	return w.checkProductionReceiving()
}

// checkProductionReceiving is what receiving credentials needs in
// production: fapigo/client's production assurance, checked here first
// to say what to change.
func (w *Wallet) checkProductionReceiving() error {
	switch {
	case w.cfg.RequestRefresh && !w.deps.Grants.Durable():
		return errors.New("walletflow: refreshing credentials in production needs a Durable Dependencies.Grants, so a refresh token survives a restart")
	case !durableKeys(w.deps.Keys):
		return errors.New("walletflow: receiving credentials in production needs Dependencies.Keys to declare durable custody (keys.KeyCustodyAssurance)")
	case w.deps.Random != rand.Reader:
		return errors.New("walletflow: receiving credentials in production needs Dependencies.Random to be nil or crypto/rand.Reader")
	case !w.systemClock:
		return errors.New("walletflow: receiving credentials in production needs Dependencies.Clock to be nil, the system clock")
	}
	return nil
}

// checkAuthorizationCode reports what the authorization code grant needs
// that w lacks, beyond checkIssuance: a redirect URI, and in production
// a Durable Authorizations store, so an authorization survives the app
// being suspended.
func (w *Wallet) checkAuthorizationCode() error {
	switch {
	case w.cfg.RedirectURI == "":
		return fmt.Errorf("walletflow: Config.RedirectURI is required to receive credentials with the authorization code grant: %w", ErrNotConfigured)
	case !w.cfg.Development && !w.deps.Authorizations.Durable():
		return errors.New("walletflow: receiving credentials in production needs a Durable Dependencies.Authorizations, so an authorization survives the app being suspended")
	}
	return nil
}

// durableKeys reports whether ks declares it keeps its keys durably.
func durableKeys(ks KeyStore) bool {
	c, ok := ks.(keys.KeyCustodyAssurance)
	return ok && c.KeyCustody().Durable
}

// defaultHTTPClient is the client New uses when Dependencies.HTTP is
// nil. Outside Development it dials only public addresses, resolved
// once and checked at dial time, and follows no redirect: an offer's or
// a Verifier's endpoints can't point the wallet's requests into its own
// network. In Development, services on the machine or the local network
// are the point. Either checks pins, when there are any.
func defaultHTTPClient(development bool, pins TLSPins) (*http.Client, error) {
	var verify func(tls.ConnectionState) error
	if len(pins) > 0 {
		verify = pins.VerifyConnection
	}
	if development {
		if verify == nil {
			return &http.Client{Timeout: httpTimeout}, nil
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, VerifyConnection: verify}
		return &http.Client{Transport: transport, Timeout: httpTimeout}, nil
	}
	client, err := fapihttp.NewClient(fapihttp.TransportConfig{DialTimeout: httpTimeout, TLSHandshakeTimeout: httpTimeout, VerifyConnection: verify})
	if err != nil {
		return nil, fmt.Errorf("walletflow: http client: %w", err)
	}
	client.Timeout = httpTimeout
	return client, nil
}

// holdKey records that an open issuance holds key id.
func (w *Wallet) holdKey(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.liveKeys[id]++
}

// unholdKey records that an issuance no longer holds key id.
func (w *Wallet) unholdKey(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.liveKeys[id] <= 1 {
		delete(w.liveKeys, id)
	} else {
		w.liveKeys[id]--
	}
}

// keyHeld reports whether an open issuance holds key id.
func (w *Wallet) keyHeld(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.liveKeys[id] > 0
}
