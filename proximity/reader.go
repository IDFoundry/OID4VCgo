package proximity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// ReaderSession is the mdoc reader (verifier) side of one proximity
// session: it reads the mdoc's QR engagement, sends one request and
// verifies the response. It isn't safe for concurrent use.
type ReaderSession struct {
	eReaderKey      *ecdsa.PrivateKey
	eReaderKeyBytes []byte // the COSE_Key, as sent in EReaderKeyBytes
	engagement      parsedEngagement

	sessionTranscriptBytes []byte
	cipher                 *cipherState
	readerAuth             *readerKey
	maxClockSkew           time.Duration
	signerPolicy           func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	issuerRevocation       certrevocation.Checker
	rootsByDocType         map[string]*x509.CertPool
	assurance              verifier.AssuranceLevel
	issuerAuthorized       func(ctx context.Context, a verifier.IssuerAuthorization) error
	status                 *verifier.StatusPolicy

	docType   string
	requested requestedSet
	sent      bool
	closed    bool
}

type readerConfig struct {
	readerAuth          *readerKey
	maxClockSkew        time.Duration
	signerPolicy        func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	issuerRevocation    certrevocation.Checker
	rootsByDocType      map[string]*x509.CertPool
	assurance           verifier.AssuranceLevel
	issuerAuthorized    func(ctx context.Context, a verifier.IssuerAuthorization) error
	anyIssuerForAnyType bool
	status              *verifier.StatusPolicy
	noStatusCheck       bool
}

// ReaderOption configures NewReaderSession.
type ReaderOption func(*readerConfig)

// WithReaderAuth signs the request as the reader whose key is signer —
// P-256 ECDSA or Ed25519 — and whose certificate chain, leaf first, is
// chain (§9.1.4): Establishment adds a readerAuth, which the holder
// verifies to show who is asking. The leaf certifies signer's public
// key, and should carry ReaderAuthenticationEKU.
func WithReaderAuth(signer crypto.Signer, chain []*x509.Certificate) ReaderOption {
	return func(c *readerConfig) { c.readerAuth = &readerKey{signer: signer, chain: slices.Clone(chain)} }
}

// MaxReaderClockSkew is the most WithMaxClockSkew allows: a larger
// allowance would all but switch off the MSO's validity check.
const MaxReaderClockSkew = time.Hour

// WithMaxClockSkew tolerates a reader clock up to d off the issuer's:
// Verify accepts an MSO up to d before its validFrom and after its
// validUntil (credential/mdoc.VerifyOptions.MaxClockSkew). Without it,
// a freshly issued mdoc is refused when the reader's clock runs behind
// the issuer's. NewReaderSession refuses more than MaxReaderClockSkew.
func WithMaxClockSkew(d time.Duration) ReaderOption {
	return func(c *readerConfig) { c.maxClockSkew = d }
}

// WithDocumentSignerPolicy runs policy on the chain-verified document
// signer certificate and its verified paths, in place of
// DefaultDocumentSignerPolicy, and Verify refuses the document when it
// fails. Chain validation accepts a leaf with any key usage; the
// default refuses the certificates an IACA issues for other jobs,
// requiring the extended key usage ISO/IEC 18013-5 Annex B.1.4
// profiles an mDL document signer with, as RequireMDLDocumentSignerEKU
// does. mdoc.LenientDocumentSignerPolicy also accepts a certificate
// with no extended key usage extension, and AnyDocumentSigner checks
// nothing.
func WithDocumentSignerPolicy(policy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error) ReaderOption {
	return func(c *readerConfig) { c.signerPolicy = policy }
}

// WithIssuerRevocation checks the document signer's certificate chain
// for revocation with checker: Verify accepts the document only through
// a verified path the document signer policy approves and checker
// passes, and refuses one whose signer or intermediate is revoked with
// an error wrapping certrevocation.ErrRevoked. checker is asked with
// Verify's context. It's REQUIRED, as a verifier's issuer trust's
// Revocation is: certrevocation.CRLs{...} (a certrevocation.Refresher's
// Checker), a certrevocation.Checker of your own, or
// certrevocation.NoCheck{} to decline checking explicitly; without it,
// or with nil, NewReaderSession fails. It's the document signer's
// certificate; the document's own revocation is its status list
// (WithStatus).
func WithIssuerRevocation(checker certrevocation.Checker) ReaderOption {
	return func(c *readerConfig) { c.issuerRevocation = checker }
}

// WithAssurance sets the reader's assurance level, as
// verifier.Config.Assurance does a Verifier's: REQUIRED,
// verifier.AssuranceDevelopment or verifier.AssuranceProduction. Under
// verifier.AssuranceProduction, NewReaderSession requires the decisions
// a Verifier makes there, so none is left to a default that silently
// accepts what it shouldn't:
//
//   - which issuers may issue which document types: WithIssuerAuthorization,
//     or WithAnyIssuerForAnyType;
//   - the documents' revocation status: WithStatus, or WithNoStatusCheck
//     (verifier.CheckStatusDecision);
//   - neither Verify's roots nor WithIssuerRootsByDocType's may be the
//     system root pool, which anchors every public CA's certificates.
//
// The document signer's revocation (WithIssuerRevocation) is required
// at either level.
func WithAssurance(level verifier.AssuranceLevel) ReaderOption {
	return func(c *readerConfig) { c.assurance = level }
}

// WithIssuerAuthorization decides whether a verified document's issuer
// may issue its document type, as verifier.VerifyResponseRequest's
// IssuerAuthorized does: Verify calls authorized with the document's
// type (Type, RequestedTypes and MatchedTypes, all the requested
// doctype), claims and issuer chain (Verified.Credential's), and an
// error refuses the document. Decide on IssuerChain, never on the
// common names a document signer chooses itself.
func WithIssuerAuthorization(authorized func(ctx context.Context, a verifier.IssuerAuthorization) error) ReaderOption {
	return func(c *readerConfig) { c.issuerAuthorized = authorized }
}

// WithAnyIssuerForAnyType declares that every issuer the reader's roots
// trust may issue every document type it requests, so
// WithIssuerAuthorization is deliberately left out
// (verifier.VerifyResponseRequest.AnyIssuerForAnyType): where the roots
// are one ecosystem's, or WithIssuerRootsByDocType gives each type its
// own.
func WithAnyIssuerForAnyType() ReaderOption {
	return func(c *readerConfig) { c.anyIssuerForAnyType = true }
}

// WithStatus checks the verified document's revocation status with
// policy, as mdocdcapi.VerifyParams.Status does: Verify refuses a
// document that isn't valid on its status list, is on its identifier
// list, or whose status can't be read, with the list's signer bound to
// the document's issuer through Verified.Credential's IssuerChain
// (ISO/IEC 18013-5 §12.3.6.2). The check fetches the list, with
// Verify's context.
func WithStatus(policy *verifier.StatusPolicy) ReaderOption {
	return func(c *readerConfig) {
		c.status = nil
		if policy != nil {
			p := *policy
			c.status = &p
		}
	}
}

// WithNoStatusCheck declares that this reader deliberately checks no
// revocation status, so WithStatus is left out
// (verifier.CheckStatusDecision): a caller checking Verified.Status
// itself, after Verify, sets it too.
func WithNoStatusCheck() ReaderOption {
	return func(c *readerConfig) { c.noStatusCheck = true }
}

// WithIssuerRootsByDocType holds each document type to its own trust
// anchors: Verify checks a document of a type roots names against that
// type's anchors instead of the roots it's given. Without it, every
// anchor Verify is given may sign every document type, a PID issuer's
// an mDL, say: where the anchors come from different ecosystems, name
// each one's types here.
func WithIssuerRootsByDocType(roots map[string]*x509.CertPool) ReaderOption {
	return func(c *readerConfig) { c.rootsByDocType = maps.Clone(roots) }
}

// DefaultDocumentSignerPolicy is the document signer check Verify makes
// unless WithDocumentSignerPolicy replaces it: mdoc.DefaultDocumentSignerPolicy,
// which refuses the end-entity certificates an IACA issues for other
// jobs, and requires MDLDocumentSignerEKU.
func DefaultDocumentSignerPolicy(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return mdoc.DefaultDocumentSignerPolicy(leaf, chains)
}

// AnyDocumentSigner is a WithDocumentSignerPolicy policy accepting any
// certificate chain validation accepts.
func AnyDocumentSigner(*x509.Certificate, [][]*x509.Certificate) error { return nil }

// MDLDocumentSignerEKU is the extended key usage of an mDL document
// signer certificate (ISO/IEC 18013-5 Annex B: id-mdl-kp-mdlDS,
// 1.0.18013.5.1.2): mdoc.MDLDocumentSignerEKU.
var MDLDocumentSignerEKU = mdoc.MDLDocumentSignerEKU

// RequireMDLDocumentSignerEKU is a WithDocumentSignerPolicy policy
// refusing a document signer certificate without MDLDocumentSignerEKU,
// or whose every verified path has an intermediate CA whose own
// extended key usage excludes it. DefaultDocumentSignerPolicy requires
// it too, and refuses an OCSP signer's certificate or one whose key
// usage doesn't allow digital signatures besides.
func RequireMDLDocumentSignerEKU(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	if err := certchain.EKUInPath(leaf, chains, MDLDocumentSignerEKU); err != nil {
		return fmt.Errorf("the document signer certificate isn't an mDL document signer's (1.0.18013.5.1.2): %w", err)
	}
	return nil
}

// NewReaderSession decodes the mdoc's QR code (§8.2.2.3), checks its
// DeviceEngagement offers cipher suite 1, generates the reader's
// ephemeral key (EReaderKey) and derives the session keys (§9.1.5).
func NewReaderSession(qr string, opts ...ReaderOption) (*ReaderSession, error) {
	var cfg readerConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	de, err := decodeQR(qr)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("proximity: generate EReaderKey: %w", err)
	}
	r, err := newReaderSession(key, de, nullHandover)
	if err != nil {
		return nil, err
	}
	if !r.engagement.ble {
		return nil, fmt.Errorf("proximity: DeviceEngagement offers no BLE retrieval method")
	}
	if err := configureReader(r, cfg); err != nil {
		return nil, err
	}
	return r, nil
}

// configureReader applies the same authentication, trust and policy
// decisions to every engagement mechanism.
func configureReader(r *ReaderSession, cfg readerConfig) error {
	if cfg.maxClockSkew > MaxReaderClockSkew {
		return fmt.Errorf("proximity: clock skew allowance %s is more than %s", cfg.maxClockSkew, MaxReaderClockSkew)
	}
	if cfg.signerPolicy == nil {
		cfg.signerPolicy = DefaultDocumentSignerPolicy
	}
	if err := checkDecisions(cfg); err != nil {
		return fmt.Errorf("proximity: %w", err)
	}
	if err := certchain.ValidateRevocation(cfg.issuerRevocation); err != nil {
		return fmt.Errorf("proximity: issuer revocation: %w", err)
	}
	if cfg.readerAuth != nil {
		if _, err := readerauth.CheckKey(cfg.readerAuth.signer, cfg.readerAuth.chain); err != nil {
			return fmt.Errorf("proximity: reader authentication: %w", err)
		}
	}
	r.readerAuth, r.maxClockSkew, r.signerPolicy = cfg.readerAuth, cfg.maxClockSkew, cfg.signerPolicy
	r.rootsByDocType, r.issuerRevocation = cfg.rootsByDocType, cfg.issuerRevocation
	r.assurance, r.issuerAuthorized, r.status = cfg.assurance, cfg.issuerAuthorized, cfg.status
	return nil
}

// checkDecisions refuses a configuration without an assurance level or
// a revocation choice for the document signer, and under
// verifier.AssuranceProduction one that leaves a decision WithAssurance
// lists undecided.
func checkDecisions(cfg readerConfig) error {
	switch cfg.assurance {
	case verifier.AssuranceDevelopment, verifier.AssuranceProduction:
	default:
		return errors.New("an assurance level is required: WithAssurance(verifier.AssuranceDevelopment) or WithAssurance(verifier.AssuranceProduction)")
	}
	if cfg.issuerRevocation == nil {
		return fmt.Errorf("WithIssuerRevocation is required: %s", certchain.RevocationChoices)
	}
	if err := verifier.CheckStatusDecision(cfg.assurance, cfg.status, cfg.noStatusCheck); err != nil {
		return fmt.Errorf("status decision: %w", err)
	}
	if cfg.assurance != verifier.AssuranceProduction {
		return nil
	}
	if cfg.issuerAuthorized == nil && !cfg.anyIssuerForAnyType {
		return errors.New("under AssuranceProduction, set WithIssuerAuthorization (which issuers may issue which document types) or WithAnyIssuerForAnyType: without either, any trusted issuer is accepted for any document type")
	}
	for docType, roots := range cfg.rootsByDocType {
		if certchain.IsSystemPool(roots) {
			return fmt.Errorf("under AssuranceProduction, WithIssuerRootsByDocType's roots for %q are the system root pool: it anchors every public CA's certificates; trust the IACAs", docType)
		}
	}
	return nil
}

// newReaderSession is the engagement-independent constructor, as for
// newDeviceSession.
func newReaderSession(key *ecdsa.PrivateKey, deviceEngagement []byte, handover cbor.RawMessage) (*ReaderSession, error) {
	pe, err := parseDeviceEngagement(deviceEngagement)
	if err != nil {
		return nil, err
	}
	eReaderKeyBytes, err := encodeCoseKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	transcript, err := buildSessionTranscriptBytes(deviceEngagement, eReaderKeyBytes, handover)
	if err != nil {
		return nil, err
	}
	cs, err := newSessionCipher(key, pe.eDeviceKey, transcript, true)
	if err != nil {
		return nil, err
	}
	return &ReaderSession{
		eReaderKey: key, eReaderKeyBytes: eReaderKeyBytes, engagement: pe,
		sessionTranscriptBytes: transcript, cipher: cs,
	}, nil
}

// ServiceUUID is the BLE service UUID from the mdoc's engagement, in
// 8-4-4-4-12 form.
func (r *ReaderSession) ServiceUUID() string { return formatUUID(r.engagement.uuid) }

// BLEMode is the BLE mode the mdoc's engagement offers: with
// PeripheralServer the reader scans for ServiceUUID as central; with
// CentralClient it advertises it as peripheral.
func (r *ReaderSession) BLEMode() BLEMode { return r.engagement.bleMode }

// BLEIdent is the value to serve on the Ident characteristic in mdoc
// central client mode (§8.3.3.1.1), where the reader is the GATT
// server. Peripheral server mode doesn't use it.
func (r *ReaderSession) BLEIdent() []byte { return bleIdent(r.engagement.eDeviceKeyBytes) }

// SessionTranscriptBytes is §9.1.5.1's SessionTranscriptBytes, which
// the mdoc's device authentication covers.
func (r *ReaderSession) SessionTranscriptBytes() []byte { return r.sessionTranscriptBytes }

// Establishment builds the reader's first message (§9.1.1.4): a
// SessionEstablishment carrying EReaderKey and the encrypted
// DeviceRequest for docType and elements (namespace → element
// identifiers). Verify then accepts only these elements back.
func (r *ReaderSession) Establishment(docType string, elements map[string][]string) ([]byte, error) {
	if r.closed {
		return nil, ErrSessionClosed
	}
	if r.sent {
		return nil, fmt.Errorf("proximity: SessionEstablishment already sent")
	}
	var sign func([]byte) ([]byte, error)
	if r.readerAuth != nil {
		sign = func(items []byte) ([]byte, error) { return r.readerAuth.sign(r.sessionTranscriptBytes, items) }
	}
	req, err := encodeDeviceRequest(docType, elements, sign)
	if err != nil {
		return nil, err
	}
	msg, err := r.establishment(req)
	if err != nil {
		return nil, err
	}
	r.docType, r.requested = docType, newRequestedSet(elements)
	return msg, nil
}

// establishment encrypts deviceRequest into a SessionEstablishment.
func (r *ReaderSession) establishment(deviceRequest []byte) ([]byte, error) {
	ct, err := r.cipher.encrypt(deviceRequest)
	if err != nil {
		return nil, err
	}
	eReaderKeyBytes, err := wrapTag24(r.eReaderKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("proximity: encode EReaderKeyBytes: %w", err)
	}
	msg, err := encMode.Marshal(sessionEstablishment{EReaderKey: eReaderKeyBytes, Data: ct})
	if err != nil {
		return nil, fmt.Errorf("proximity: encode SessionEstablishment: %w", err)
	}
	r.sent = true
	return msg, nil
}

// Verified is a verified proximity presentation.
type Verified struct {
	// DocType is the document's type, the one requested.
	DocType string

	// Claims are the disclosed issuer-signed elements: namespace →
	// element identifier → value, as credential/mdoc decodes them.
	Claims map[string]map[string]interface{}

	// DeviceSignedClaims are any device-signed elements (§8.3.2.1.2.2),
	// nil when there are none.
	DeviceSignedClaims map[string]map[string]interface{}

	// IssuerCN is the document signer certificate's subject common
	// name; TrustAnchorCN is the common name of the root in roots its
	// chain verified to. Both are for display: any document signer
	// under any trusted root names itself, so authorize on IssuerChain.
	IssuerCN      string
	TrustAnchorCN string

	// IssuerChain is the document signer's verified certificate path,
	// leaf first, ending at the trusted root: the one ISO/IEC 18013-5's
	// document signer checks passed on. Decide which issuers to accept
	// from it, and bind the status list's signer to it with
	// mdoc.StatusTrust(Status.StatusList, IssuerChain).
	IssuerChain []*x509.Certificate

	// ValidFrom and ValidUntil are the MSO's validity, which Verify
	// checked against the reader's clock and its allowed skew.
	ValidFrom  time.Time
	ValidUntil time.Time

	// DeviceAuth is how the mdoc authenticated: DeviceAuthSignature or
	// DeviceAuthMAC.
	DeviceAuth mdoc.DeviceAuthType

	// Status is the MSO's revocation reference (§12.3.6), nil when it
	// has none. WithStatus checks it in Verify, as §9.3.3's verification
	// includes revocation; under WithNoStatusCheck, nothing has.
	Status *mdoc.Status
}

// Credential is v as a verifier.VerifiedCredential — its Claims, Status
// and IssuerChain — for what takes one, such as
// verifier.StatusPolicy.Check or verifier.RequireValidStatus. Its
// IssuerChain is v's as DER without the trust anchor, as a Verifier's
// mdoc's is (the anchor stays when it's the only certificate); its
// CredentialQueryID is "": an ISO/IEC 18013-5 request has no DCQL
// query.
func (v Verified) Credential() verifier.VerifiedCredential {
	claims := make(map[string]any, len(v.Claims))
	for ns, elements := range v.Claims {
		claims[ns] = elements
	}
	path := v.IssuerChain
	if len(path) > 1 {
		path = path[:len(path)-1]
	}
	chain := make([][]byte, len(path))
	for i, c := range path {
		chain[i] = c.Raw
	}
	return verifier.VerifiedCredential{Claims: claims, MdocStatus: v.Status, IssuerChain: chain}
}

// Verify decrypts the mdoc's reply and verifies the DeviceResponse in
// it, at now (zero means the current time):
//
//   - the issuer's certificate chain (IssuerAuth's x5chain) verifies to
//     a root in roots, through a path the document signer policy
//     approves and WithIssuerRevocation's checker passes;
//   - the document's docType is the one requested, and the MSO's;
//   - credential/mdoc.Verify passes: issuer signature, value digests,
//     validity;
//   - device authentication — signature or MAC — verifies against the
//     MSO's device key over this session's transcript, and any
//     device-signed elements are within the MSO's key authorizations;
//   - every returned element was requested;
//   - WithIssuerAuthorization, if set, accepts the issuer for the
//     document type;
//   - WithStatus, if set, finds the document not revoked.
//
// It doesn't check that the requested elements came back: the holder
// may withhold any of them, and an empty Claims verifies. Check each
// element you need is there. ctx bounds the revocation and status
// checks, which may fetch from the network.
//
// A reply carrying only status 20 is ErrDeclined; a DeviceResponse with
// no documents is ErrNoDocument. Errors that wrap ErrSessionEncryption
// or ErrCBORDecoding have a status reply (StatusFor). Any reply ends
// the session, since this reader sends one request.
func (r *ReaderSession) Verify(ctx context.Context, msg []byte, roots *x509.CertPool, now time.Time) (Verified, error) {
	if r.closed {
		return Verified{}, ErrSessionClosed
	}
	if !r.sent {
		return Verified{}, fmt.Errorf("proximity: no request sent")
	}
	r.closed = true
	defer r.close()
	if now.IsZero() {
		now = time.Now()
	}
	if r.assurance == verifier.AssuranceProduction && certchain.IsSystemPool(roots) {
		return Verified{}, errors.New("proximity: under AssuranceProduction, roots is the system root pool: it anchors every public CA's certificates; trust the IACAs")
	}

	data, status, err := receive(r.cipher, msg)
	if err != nil {
		return Verified{}, err
	}
	if data == nil {
		if *status == StatusSessionTermination {
			return Verified{}, ErrDeclined
		}
		return Verified{}, fmt.Errorf("proximity: mdoc ended the session with status %d", *status)
	}
	doc, err := parseDeviceResponse(data)
	if err != nil {
		return Verified{}, err
	}
	v, err := r.verifyDocument(ctx, doc, roots, now)
	if err != nil {
		return Verified{}, err
	}
	if err := r.authorize(ctx, v); err != nil {
		return Verified{}, err
	}
	return v, nil
}

// authorize runs the reader's issuer authorization and status check on
// v, a verified document.
func (r *ReaderSession) authorize(ctx context.Context, v Verified) error {
	credential := v.Credential()
	if r.issuerAuthorized != nil {
		if err := r.issuerAuthorized(ctx, verifier.IssuerAuthorization{
			Format: mdoc.CredentialFormat, Type: v.DocType, RequestedTypes: []string{r.docType}, MatchedTypes: []string{v.DocType},
			IssuerChain: credential.IssuerChain, Claims: credential.Claims,
		}); err != nil {
			return fmt.Errorf("proximity: issuer authorization: %w", err)
		}
	}
	if r.status != nil {
		if err := r.status.Check(ctx, credential); err != nil {
			return fmt.Errorf("proximity: %w", err)
		}
	}
	return nil
}

func (r *ReaderSession) verifyDocument(ctx context.Context, doc responseDocument, roots *x509.CertPool, now time.Time) (Verified, error) {
	if doc.docType != r.docType {
		return Verified{}, fmt.Errorf("proximity: document docType %q, requested %q", doc.docType, r.docType)
	}

	// The size credential/mdoc verifies IssuerAuth up to.
	protected, unprotected, _, err := cose.DecodeUnverified(doc.issuerSigned.IssuerAuth)
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: decode IssuerAuth: %w", err)
	}
	chain := cose.X5ChainOf(protected, unprotected)
	if len(chain) == 0 {
		return Verified{}, fmt.Errorf("proximity: IssuerAuth has no x5chain")
	}
	if byType, ok := r.rootsByDocType[doc.docType]; ok {
		// A document type named with no roots falls back to none: the
		// general roots weren't chosen for it.
		if byType == nil {
			return Verified{}, fmt.Errorf("proximity: no issuer roots for %q", doc.docType)
		}
		roots = byType
	}
	leaf, chains, err := certchain.VerifyChainsAt(chain, roots, now)
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: issuer certificate: %w", err)
	}
	// Only the paths the policy approves on their own, and revocation
	// passes: the issuer chain reported, and the status list's signer
	// bound to, is one of them.
	if chains, err = certchain.ApprovedChains(leaf, chains, r.signerPolicy); err != nil {
		return Verified{}, fmt.Errorf("proximity: document signer certificate: %w", err)
	}
	if chains, err = certchain.NotRevokedChains(ctx, chains, r.issuerRevocation, now); err != nil {
		return Verified{}, fmt.Errorf("proximity: document signer certificate: %w", err)
	}
	// The algorithm is the verified certificate's key's (ISO/IEC
	// 18013-5 §9.3.1: its working public key algorithm), never the
	// document's own header's, which IssuerAuth must then match.
	issuerAlg, err := keyAlg(leaf.PublicKey)
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: document signer key: %w", err)
	}
	verified, err := mdoc.Verify(doc.issuerSigned, r.docType, leaf.PublicKey, issuerAlg, mdoc.VerifyOptions{
		Now: func() time.Time { return now }, MaxClockSkew: r.maxClockSkew,
	})
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: %w", err)
	}
	// §9.3.3's IACA subject checks, §9.3.1 step 5's signed date, and
	// an mDL's issuing_country and issuing_jurisdiction.
	anchored, err := mdoc.CheckDocumentSigner(verified, chains)
	if err != nil {
		return Verified{}, fmt.Errorf("proximity: %w", err)
	}

	switch doc.deviceSigned.AuthType {
	case mdoc.DeviceAuthSignature:
		alg, err := keyAlg(verified.DeviceKey)
		if err != nil {
			return Verified{}, fmt.Errorf("proximity: MSO device key: %w", err)
		}
		if err := mdoc.VerifyDeviceSignature(doc.deviceSigned, verified.DeviceKey, alg, r.sessionTranscriptBytes, r.docType); err != nil {
			return Verified{}, fmt.Errorf("proximity: %w", err)
		}
	case mdoc.DeviceAuthMAC:
		deviceKey, ok := verified.DeviceKey.(*ecdsa.PublicKey)
		if !ok {
			return Verified{}, fmt.Errorf("proximity: DeviceMAC needs a P-256 device key, the MSO has %T", verified.DeviceKey)
		}
		if err := mdoc.VerifyDeviceMAC(doc.deviceSigned, deviceKey, r.eReaderKey, r.sessionTranscriptBytes, r.docType); err != nil {
			return Verified{}, fmt.Errorf("proximity: %w", err)
		}
	default:
		return Verified{}, fmt.Errorf("proximity: unknown device authentication type %d", doc.deviceSigned.AuthType)
	}
	if err := mdoc.CheckKeyAuthorizations(doc.deviceSigned.NameSpaces, verified.KeyAuthorizations); err != nil {
		return Verified{}, fmt.Errorf("proximity: %w", err)
	}

	if extra := r.requested.unrequested(verified.NameSpaces); len(extra) > 0 {
		return Verified{}, fmt.Errorf("proximity: response carries unrequested elements %v", extra)
	}
	if extra := r.requested.unrequested(doc.deviceSigned.NameSpaces); len(extra) > 0 {
		return Verified{}, fmt.Errorf("proximity: response carries unrequested device-signed elements %v", extra)
	}

	out := Verified{
		DocType:     verified.DocType,
		Claims:      verified.NameSpaces,
		IssuerCN:    leaf.Subject.CommonName,
		ValidFrom:   verified.ValidityInfo.ValidFrom,
		ValidUntil:  verified.ValidityInfo.ValidUntil,
		DeviceAuth:  doc.deviceSigned.AuthType,
		Status:      verified.Status,
		IssuerChain: anchored,
	}
	if len(doc.deviceSigned.NameSpaces) > 0 {
		out.DeviceSignedClaims = doc.deviceSigned.NameSpaces
	}
	// The root of the path the §9.3.3 checks passed on.
	out.TrustAnchorCN = anchored[len(anchored)-1].Subject.CommonName
	return out, nil
}

// Termination builds a SessionData carrying only status 20 and closes
// the session.
func (r *ReaderSession) Termination() []byte {
	r.close()
	return StatusMessage(StatusSessionTermination)
}

// close ends the session and drops its secrets: EReaderKey and the
// session keys. A closed session refuses every further message, so
// nothing needs them, and a later compromise of the process can't
// decrypt what was recorded.
func (r *ReaderSession) close() {
	r.closed = true
	r.eReaderKey, r.cipher = nil, nil
}
