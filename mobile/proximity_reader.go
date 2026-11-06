package mobile

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// ProximityReader is an ISO/IEC 18013-5 mdoc reader: a verifier asking
// for an mdoc in person, over BLE (package proximity). It's
// independent of Wallet: a verifier app needs no wallet. Start a
// ProximityReaderSession for each holder.
type ProximityReader struct {
	roots    *x509.CertPool
	opts     []proximity.ReaderOption
	clock    func() time.Time
	readerCN string
	// crls are the lists the "revocation" roles check against, and
	// statusRevocation, when "status" is named, the check on a status
	// list's signer.
	crls             *crlSet
	statusRevocation certrevocation.Checker
	// checksStatus is the configuration's "status": "check".
	checksStatus bool
	// statusMaxBytes and identifierListMaxBytes are the configuration's
	// "status_max_bytes" and "identifier_list_max_bytes".
	statusMaxBytes, identifierListMaxBytes int
	// statusCache keeps the lists it checks, for the configuration's
	// "status_cache_max_age_seconds".
	statusCache *statuslist.Cache
}

// A reader configuration's "status" values.
const (
	statusCheck   = "check"
	statusDecline = "decline"
)

// proximityReaderConfig is NewProximityReader's configuration.
type proximityReaderConfig struct {
	// IssuerRoots are PEM certificates: the IACAs whose mdocs the
	// reader accepts, of any document type IssuerRootsByDocType doesn't
	// name. Optional when IssuerRootsByDocType is set: then only its
	// types are accepted.
	IssuerRoots string `json:"issuer_roots,omitempty"`
	// IssuerRootsByDocType are each document type's own IACAs, as PEM
	// certificates: a document of a type it names must chain to them,
	// not to IssuerRoots, so an issuer trusted for one document type
	// can't sign another.
	IssuerRootsByDocType map[string]string `json:"issuer_roots_by_doctype,omitempty"`
	// ReaderKeyID names the reader's key in the KeyStore, and
	// ReaderChain is its PEM certificate chain, leaf first: with both,
	// requests are signed (reader authentication), so a holder sees who
	// asks. The leaf should carry the mdoc reader authentication
	// extended key usage.
	ReaderKeyID string `json:"reader_key_id,omitempty"`
	ReaderChain string `json:"reader_chain,omitempty"`
	// MaxClockSkewSeconds tolerates a holder's issuer's clock that far
	// off the reader's (at most an hour).
	MaxClockSkewSeconds int64 `json:"max_clock_skew_seconds,omitempty"`
	// StatusMaxBytes and IdentifierListMaxBytes are the largest status
	// list and identifier list CheckStatus reads, as a Wallet's.
	StatusMaxBytes         int `json:"status_max_bytes,omitempty"`
	IdentifierListMaxBytes int `json:"identifier_list_max_bytes,omitempty"`
	// StatusCacheMaxAgeSeconds is how long a status or identifier list
	// fetched is used, StatusCacheDir where lists are kept across
	// launches, and StatusCacheKey what authenticates them there, as a
	// Wallet's.
	StatusCacheMaxAgeSeconds int64  `json:"status_cache_max_age_seconds,omitempty"`
	StatusCacheDir           string `json:"status_cache_dir,omitempty"`
	StatusCacheKey           string `json:"status_cache_key,omitempty"`
	// RequireMDLSignerEKU accepts only document signer certificates
	// with the mDL document signer extended key usage. The default
	// check (proximity.DefaultDocumentSignerPolicy) requires it too.
	RequireMDLSignerEKU bool `json:"require_mdl_signer_eku,omitempty"`
	// AcceptMDLSignerWithoutEKU also accepts a document signer
	// certificate with no extended key usage extension, which the
	// default check refuses for lacking the mDL document signer's
	// (mdoc.LenientDocumentSignerPolicy), for issuers whose document
	// signers have none. It can't be set with RequireMDLSignerEKU.
	AcceptMDLSignerWithoutEKU bool `json:"accept_mdl_signer_without_eku,omitempty"`
	// CRLs are PEM "X509 CRL" blocks, replaced later by SetCRLs, and
	// Revocation the roles whose certificate chains must pass a CRL
	// check: "issuer", the document signer's
	// (proximity.WithIssuerRevocation), and "status", a status list
	// signer's in CheckStatus. A role named fails closed for any CA it
	// has no current CRL from.
	CRLs       string   `json:"crls,omitempty"`
	Revocation []string `json:"revocation,omitempty"`
	// CRLIssuers are PEM certificates of the CAs that issued
	// certificates pinned in the roots, as a Wallet's crl_issuers.
	CRLIssuers string `json:"crl_issuers,omitempty"`
	// CRLDistributionPoints, CRLDistributionPointsFromRoots and
	// CRLRequireHTTPS configure RefreshCRLs, as a Wallet's.
	CRLDistributionPoints          []crlDistributionPoint `json:"crl_distribution_points,omitempty"`
	CRLDistributionPointsFromRoots bool                   `json:"crl_distribution_points_from_roots,omitempty"`
	CRLRequireHTTPS                bool                   `json:"crl_require_https,omitempty"`
	// DevelopmentRoots are PEM certificates RefreshCRLs's HTTPS fetches
	// trust besides the system's, as a Wallet's development_roots: a
	// development CA's distribution points served under its own TLS
	// certificate, which Go on Android can't otherwise be given. Only
	// with Development.
	DevelopmentRoots string `json:"development_roots,omitempty"`
	// NoRevocationCheck names the roles, of Revocation's, that decline
	// checking revocation (certrevocation.NoCheck). Outside Development,
	// each role must be named in one of the two; a role can't be in
	// both. In development, a role in neither checks no revocation.
	NoRevocationCheck []string `json:"no_revocation_check,omitempty"`
	// AnyIssuerForAnyType declares that every IACA in IssuerRoots may
	// issue every document type the reader asks for
	// (proximity.WithAnyIssuerForAnyType). Outside Development,
	// IssuerRoots needs it: otherwise name each document type's IACAs in
	// IssuerRootsByDocType.
	AnyIssuerForAnyType bool `json:"any_issuer_for_any_type,omitempty"`
	// Status is whether a verified document's revocation status is
	// checked before the session reports it: "check" or "decline"
	// (statusCheck, statusDecline). Outside Development, one is required.
	// With "check", the wrappers call CheckStatus themselves once the
	// holder's answer verifies, and report the session verified only on
	// "valid" or "none" (check_status in Engagement); with "decline",
	// nothing checks it, for a reader where something else stands in.
	// In development, unset is "decline".
	Status string `json:"status,omitempty"`
	// Development relaxes what production requires, for a reader trying
	// out a development issuer's documents. Never ship an app with it
	// set. Without it, the reader runs at production assurance
	// (proximity.WithAssurance with verifier.AssuranceProduction) and
	// requires a production reader's decisions: each role's revocation,
	// and which IACAs issue which document types. With it, the reader
	// runs at development assurance, any IACA in IssuerRoots may issue
	// any document type, and a role left out of Revocation and
	// NoRevocationCheck checks no revocation.
	Development bool `json:"development"`
}

// readerDocumentSignerPolicy is the document signer check cfg asks
// for, or nil for proximity's default.
func readerDocumentSignerPolicy(cfg proximityReaderConfig) (func(*x509.Certificate, [][]*x509.Certificate) error, error) {
	switch {
	case cfg.RequireMDLSignerEKU && cfg.AcceptMDLSignerWithoutEKU:
		return nil, newError(CodeInvalidInput, errors.New("require_mdl_signer_eku and accept_mdl_signer_without_eku can't both be set"))
	case cfg.RequireMDLSignerEKU:
		return proximity.RequireMDLDocumentSignerEKU, nil
	case cfg.AcceptMDLSignerWithoutEKU:
		return mdoc.LenientDocumentSignerPolicy, nil
	}
	return nil, nil
}

// NewProximityReader configures a reader from configJSON:
// {"issuer_roots", "issuer_roots_by_doctype", "reader_key_id",
// "reader_chain", "max_clock_skew_seconds", "status_max_bytes",
// "identifier_list_max_bytes", "status_cache_max_age_seconds",
// "status_cache_dir", "require_mdl_signer_eku",
// "accept_mdl_signer_without_eku", "crls", "crl_issuers",
// "crl_distribution_points", "crl_distribution_points_from_roots",
// "crl_require_https", "revocation",
// "no_revocation_check", "any_issuer_for_any_type", "development"},
// refusing any other key, so a misspelled option isn't silently left
// at its default. Outside "development", it refuses a configuration
// that leaves a production reader's decisions open: the revocation of
// each role, and which IACAs may issue which document types. keys holds the
// reader's key, reader_key_id; it may be nil for a reader that doesn't
// sign.
func NewProximityReader(configJSON string, keys KeyStore) (*ProximityReader, error) {
	var cfg proximityReaderConfig
	if err := decodeConfig(configJSON, &cfg); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("reader config: %w", err))
	}
	var roots *x509.CertPool
	if cfg.IssuerRoots != "" || len(cfg.IssuerRootsByDocType) == 0 {
		var err error
		if roots, err = certPool(cfg.IssuerRoots); err != nil {
			return nil, newError(CodeInvalidInput, fmt.Errorf("issuer_roots: %w", err))
		}
	}
	r := &ProximityReader{roots: roots, clock: time.Now}
	if err := r.configureDecisions(cfg); err != nil {
		return nil, err
	}
	if len(cfg.IssuerRootsByDocType) > 0 {
		byType := make(map[string]*x509.CertPool, len(cfg.IssuerRootsByDocType))
		for docType, pemText := range cfg.IssuerRootsByDocType {
			pool, err := certPool(pemText)
			if err != nil {
				return nil, newError(CodeInvalidInput, fmt.Errorf("issuer_roots_by_doctype[%q]: %w", docType, err))
			}
			byType[docType] = pool
		}
		r.opts = append(r.opts, proximity.WithIssuerRootsByDocType(byType))
	}
	if cfg.MaxClockSkewSeconds != 0 {
		r.opts = append(r.opts, proximity.WithMaxClockSkew(time.Duration(cfg.MaxClockSkewSeconds)*time.Second))
	}
	switch {
	case cfg.StatusMaxBytes < 0 || cfg.StatusMaxBytes > statuslist.MaxTokenBytesLimit:
		return nil, newError(CodeInvalidInput, fmt.Errorf("status_max_bytes is %d, not between 0 and %d", cfg.StatusMaxBytes, statuslist.MaxTokenBytesLimit))
	case cfg.IdentifierListMaxBytes < 0 || cfg.IdentifierListMaxBytes > identifierlist.MaxTokenBytesLimit:
		return nil, newError(CodeInvalidInput, fmt.Errorf("identifier_list_max_bytes is %d, not between 0 and %d", cfg.IdentifierListMaxBytes, identifierlist.MaxTokenBytesLimit))
	}
	r.statusMaxBytes, r.identifierListMaxBytes = cfg.StatusMaxBytes, cfg.IdentifierListMaxBytes
	cache, err := statusCacheFor(cfg.StatusCacheMaxAgeSeconds, cfg.StatusCacheDir, cfg.StatusCacheKey)
	if err != nil {
		return nil, err
	}
	r.statusCache = cache
	policy, err := readerDocumentSignerPolicy(cfg)
	if err != nil {
		return nil, err
	}
	if policy != nil {
		r.opts = append(r.opts, proximity.WithDocumentSignerPolicy(policy))
	}
	if err := r.configureRevocation(cfg); err != nil {
		return nil, err
	}
	if err := r.configureStatus(cfg); err != nil {
		return nil, err
	}
	switch {
	case cfg.ReaderKeyID == "" && cfg.ReaderChain == "":
	case cfg.ReaderKeyID == "" || cfg.ReaderChain == "" || keys == nil:
		return nil, newError(CodeInvalidInput, errors.New("reader authentication needs reader_key_id, reader_chain and a KeyStore"))
	default:
		chain, err := parseChain(cfg.ReaderChain)
		if err != nil {
			return nil, newError(CodeInvalidInput, fmt.Errorf("reader_chain: %w", err))
		}
		key, err := keyStore{ks: keys}.load(cfg.ReaderKeyID)
		if err != nil {
			return nil, err
		}
		r.opts = append(r.opts, proximity.WithReaderAuth(key, chain))
		r.readerCN = chain[0].Subject.CommonName
	}
	// Check the options once, on a throwaway engagement, so a bad key or
	// chain fails here rather than at the first holder.
	probe, err := proximity.NewDeviceSession(nil)
	if err != nil {
		return nil, newError(CodeInternal, err)
	}
	if _, err := proximity.NewReaderSession(probe.QRCode(), r.opts...); err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return r, nil
}

// configureDecisions sets the reader's assurance and its issuer and
// status decisions, refusing, outside development, issuer_roots without
// any_issuer_for_any_type. The documents' status is CheckStatus's, a
// call of its own: HandleMessage, which runs no network request, checks
// none (proximity.WithNoStatusCheck).
func (r *ProximityReader) configureDecisions(cfg proximityReaderConfig) error {
	assurance := verifier.AssuranceDevelopment
	if !cfg.Development {
		assurance = verifier.AssuranceProduction
		if cfg.IssuerRoots != "" && !cfg.AnyIssuerForAnyType {
			return newError(CodeInvalidInput, errors.New("issuer_roots is set: outside development, set any_issuer_for_any_type to accept its IACAs for every document type, or name each document type's IACAs in issuer_roots_by_doctype"))
		}
	}
	// issuer_roots_by_doctype is the decision of which IACAs issue which
	// type; issuer_roots, any_issuer_for_any_type's.
	r.opts = append(r.opts, proximity.WithAssurance(assurance), proximity.WithAnyIssuerForAnyType(), proximity.WithNoStatusCheck())
	return nil
}

// configureStatus records cfg's "status" decision, refusing, outside
// development, a configuration that leaves it open: the Go session
// checks no status itself (HandleMessage runs no network request), so
// without it a document is reported verified whatever its revocation.
func (r *ProximityReader) configureStatus(cfg proximityReaderConfig) error {
	switch cfg.Status {
	case statusCheck:
		r.checksStatus = true
	case statusDecline:
	case "":
		if !cfg.Development {
			return newError(CodeInvalidInput, errors.New(`status is unset: outside development, set "check" to check a verified document's revocation status before the session reports it, or "decline" where something else stands in`))
		}
	default:
		return newError(CodeInvalidInput, fmt.Errorf(`status is %q, not "check" or "decline"`, cfg.Status))
	}
	return nil
}

// configureRevocation sets the revocation check of each role, as cfg's
// "revocation" and "no_revocation_check" decide, over cfg's "crls".
func (r *ProximityReader) configureRevocation(cfg proximityReaderConfig) error {
	known := []string{revocationIssuer, revocationStatus}
	named, err := revocationRoles("revocation", cfg.Revocation, known...)
	if err != nil {
		return err
	}
	declined, err := revocationRoles("no_revocation_check", cfg.NoRevocationCheck, known...)
	if err != nil {
		return err
	}
	if r.crls, err = newCRLSet(cfg.CRLs, cfg.CRLIssuers); err != nil {
		return err
	}
	roots := []string{cfg.CRLIssuers}
	if named[revocationIssuer] || named[revocationStatus] {
		roots = append(roots, cfg.IssuerRoots)
		for _, docType := range slices.Sorted(maps.Keys(cfg.IssuerRootsByDocType)) {
			roots = append(roots, cfg.IssuerRootsByDocType[docType])
		}
	}
	client, err := crlHTTP(cfg.Development, cfg.DevelopmentRoots)
	if err != nil {
		return err
	}
	if err := r.crls.configureRefresh(crlRefreshConfig{
		points: cfg.CRLDistributionPoints, fromRoots: cfg.CRLDistributionPointsFromRoots,
		roots: roots, requireHTTPS: cfg.CRLRequireHTTPS, development: cfg.Development,
		http: client,
	}); err != nil {
		return err
	}
	const rootKeys = "issuer_roots or issuer_roots_by_doctype"
	when := "outside development"
	if cfg.Development {
		when = ""
	}
	issuer, err := revocationChoice(revocationIssuer, rootKeys, true, named, declined, when, r.crls)
	if err != nil {
		return err
	}
	if issuer == nil {
		// In development, undecided: no check.
		issuer = certrevocation.NoCheck{}
	}
	r.opts = append(r.opts, proximity.WithIssuerRevocation(issuer))
	r.statusRevocation, err = revocationChoice(revocationStatus, rootKeys, true, named, declined, when, r.crls)
	return err
}

// RefreshCRLs fetches the configuration's CRL distribution points and
// keeps each current list its CA signed that isn't older than the one
// held, for sessions started before as well as after, as
// Wallet.RefreshCRLs, returning the same JSON.
func (r *ProximityReader) RefreshCRLs(op *Operation) (string, error) {
	return r.crls.refresh(op.context())
}

// SetCRLs replaces the Certificate Revocation Lists the configuration's
// "revocation" roles are checked against with pemText's "X509 CRL"
// blocks, for sessions started before as well as after: as
// Wallet.SetCRLs.
func (r *ProximityReader) SetCRLs(pemText string) error {
	if err := r.crls.set(pemText); err != nil {
		return newError(CodeInvalidInput, fmt.Errorf("crls: %w", err))
	}
	return nil
}

// parseChain parses PEM certificates, in order.
func parseChain(pemText string) ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
	}
	if len(chain) == 0 {
		return nil, errors.New("no PEM certificates")
	}
	return chain, nil
}

// ProximityReaderSession is one reader session: the reader scanned the
// holder's QR code, connects over BLE, sends one request and verifies
// the answer. The BLE transport is the app's (Engagement says its
// role). Its methods are safe to call from any thread.
type ProximityReaderSession struct {
	r       *ProximityReader
	mu      sync.Mutex
	s       *proximity.ReaderSession
	asked   bool
	stopped bool
	// verified are the mdocs HandleMessage verified, for CheckStatus.
	verified []proximity.Verified
}

// Start reads qrCode, the holder's QR code ("mdoc:…"), and derives the
// session keys. A QR code this reader can't use — not an mdoc
// engagement, no BLE, no cipher suite it supports — is invalid_input.
func (r *ProximityReader) Start(qrCode string) (*ProximityReaderSession, error) {
	s, err := proximity.NewReaderSession(qrCode, r.opts...)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &ProximityReaderSession{r: r, s: s}, nil
}

// StartFromHandover starts a reader session from a static NFC Handover
// Select NDEF message, without NLEN. It applies this reader's existing
// signer and trust configuration. The platform performs NFC I/O and
// then connects the BLE transport described by Engagement.
func (r *ProximityReader) StartFromHandover(handoverSelect []byte) (*ProximityReaderSession, error) {
	s, err := proximity.NewNFCReaderSession(handoverSelect, r.opts...)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &ProximityReaderSession{r: r, s: s}, nil
}

// Engagement returns {"abi", "service_uuid", "ble_mode", "ident",
// "signed", "check_status"}. ble_mode is the mode the reader uses, from those the holder
// offers (central client mode when it offers both, §8.3.3.1.1):
//   - "peripheral_server": the holder advertises service_uuid and is
//     the GATT server; the reader scans, connects, and is the GATT
//     client.
//   - "central_client": the reader advertises service_uuid and is the
//     GATT server, serving ident (base64) on the Ident characteristic;
//     the holder connects.
//
// signed is whether the request will carry reader authentication.
// check_status is the configuration's "status": "check": once
// HandleMessage reports "verified", call CheckStatus, and treat the
// document as verified only when it's "valid" or "none" — the Swift and
// Kotlin sessions do, reporting another status as document_not_valid.
func (p *ProximityReaderSession) Engagement() string {
	mode := "peripheral_server"
	if p.s.BLEMode() == proximity.CentralClient {
		mode = "central_client"
	}
	text, _ := marshal(struct {
		result
		ServiceUUID string `json:"service_uuid"`
		BLEMode     string `json:"ble_mode"`
		Ident       string `json:"ident"`
		Signed      bool   `json:"signed"`
		CheckStatus bool   `json:"check_status"`
	}{result{ABIVersion}, p.s.ServiceUUID(), mode, base64.StdEncoding.EncodeToString(p.s.BLEIdent()), p.r.readerCN != "", p.r.checksStatus})
	return text
}

// Request builds the request for docType's elements, elementsJSON a
// JSON object of namespace → [element identifiers], and returns
// {"abi", "send"}: send the base64 "send", the SessionEstablishment,
// once connected and State is 0x01. A reader key in a KeyStore that
// requires user presence prompts now. Once per session.
func (p *ProximityReaderSession) Request(docType, elementsJSON string) (string, error) {
	var elements map[string][]string
	if err := json.Unmarshal([]byte(elementsJSON), &elements); err != nil {
		return "", newError(CodeInvalidInput, fmt.Errorf("elements: %w", err))
	}
	return p.request([]proximity.DocumentRequest{{DocType: docType, Elements: elements}})
}

// RequestDocuments is Request asking for several documents at once:
// requestsJSON is a JSON array of {"doctype", "elements"}, elements as
// Request's, each document type once, at most eight. HandleMessage
// then reports each document the holder answers in "documents".
func (p *ProximityReaderSession) RequestDocuments(requestsJSON string) (string, error) {
	dec := json.NewDecoder(strings.NewReader(requestsJSON))
	dec.DisallowUnknownFields()
	var in []struct {
		DocType  string              `json:"doctype"`
		Elements map[string][]string `json:"elements"`
	}
	if err := dec.Decode(&in); err != nil {
		return "", newError(CodeInvalidInput, fmt.Errorf("requests: %w", err))
	}
	docs := make([]proximity.DocumentRequest, 0, len(in))
	for _, d := range in {
		docs = append(docs, proximity.DocumentRequest{DocType: d.DocType, Elements: d.Elements})
	}
	return p.request(docs)
}

func (p *ProximityReaderSession) request(docs []proximity.DocumentRequest) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.asked || p.stopped {
		return "", newError(CodeWrongStep, errors.New("the request was already sent"))
	}
	msg, err := p.s.EstablishmentDocuments(docs)
	if err != nil {
		var mobileErr *Error
		if errors.As(err, &mobileErr) {
			return "", mobileErr // the KeyStore's
		}
		return "", newError(CodeInvalidInput, err)
	}
	p.asked = true
	return marshal(struct {
		result
		Send string `json:"send"`
	}{result{ABIVersion}, base64.StdEncoding.EncodeToString(msg)})
}

type verifiedJSON struct {
	DocType            string         `json:"doctype"`
	Claims             map[string]any `json:"claims"`
	DeviceSignedClaims map[string]any `json:"device_signed_claims,omitempty"`
	Issuer             string         `json:"issuer"`
	TrustAnchor        string         `json:"trust_anchor"`
	ValidFrom          string         `json:"valid_from"`
	ValidUntil         string         `json:"valid_until"`
	DeviceAuth         string         `json:"device_auth"`
	Status             *statusRefJSON `json:"status,omitempty"`
	// IssuerChain is the document signer's verified certificate path,
	// leaf first, ending at the trusted root, as base64 DER: what to
	// decide on, where Issuer and TrustAnchor are only for display.
	IssuerChain []string `json:"issuer_chain"`
}

type statusRefJSON struct {
	// Type is "status_list" or "identifier_list" (ISO/IEC 18013-5
	// §12.3.6.2), or "unknown" for a status naming neither: a
	// mechanism this reader doesn't know, with no URI.
	Type string `json:"type"`
	URI  string `json:"uri"`
	// Idx is a status list's index.
	Idx uint64 `json:"idx,omitempty"`
	// ID is the document's identifier in an identifier list, as base64.
	ID string `json:"id,omitempty"`
	// Certificate is the list signer's trust anchor, when the MSO names
	// one, as base64 DER.
	Certificate string `json:"certificate,omitempty"`
	// IdentifierList is, on a status list's reference, the identifier
	// list the MSO names too, which CheckStatus checks as well.
	IdentifierList *statusRefJSON `json:"identifier_list,omitempty"`
}

// statusRefOf is an MSO's status reference as JSON: either mechanism,
// or both, or one it doesn't know, so a document revoked through an
// identifier list, or through another mechanism, doesn't look like one
// with no status at all.
func statusRefOf(status *mdoc.Status) *statusRefJSON {
	var identifiers *statusRefJSON
	if status != nil && status.IdentifierList != nil {
		identifiers = &statusRefJSON{
			Type: "identifier_list", URI: status.IdentifierList.URI,
			ID:          base64.StdEncoding.EncodeToString(status.IdentifierList.ID),
			Certificate: base64.StdEncoding.EncodeToString(status.IdentifierList.Certificate),
		}
	}
	switch {
	case status == nil:
		return nil
	case status.StatusList != nil:
		return &statusRefJSON{
			Type: "status_list", URI: status.StatusList.URI, Idx: status.StatusList.Idx,
			Certificate:    base64.StdEncoding.EncodeToString(status.StatusList.Certificate),
			IdentifierList: identifiers,
		}
	case identifiers != nil:
		return identifiers
	default:
		// A status naming no mechanism this reader knows still isn't
		// no status.
		return &statusRefJSON{Type: walletflow.StatusUnknown}
	}
}

// HandleMessage processes the holder's answer, one whole message
// reassembled from its BLE chunks, and returns {"abi", "event",
// "verified", "send", "reason", "error"}. The session is then over:
// send "send" (base64) if present, write 0x02 to State, and disconnect.
// event is:
//   - "verified": the mdoc verified (issuer chain to issuer_roots,
//     digests, validity, device authentication over this session, only
//     requested elements). verified is {"doctype", "claims":
//     {namespace: {identifier: value}}, "device_signed_claims",
//     "issuer", "trust_anchor", "valid_from", "valid_until",
//     "device_auth" ("signature" or "mac"), "status", "issuer_chain"}:
//     claims as the wallet's are (byte strings base64, dates their
//     text). The holder may withhold elements: check each one needed is
//     there. status, when present, is the MSO's revocation reference,
//     which isn't checked here: call CheckStatus before relying on the
//     document. issuer_chain is the document signer's verified path,
//     leaf first, ending at the trusted root, as base64 DER; issuer and
//     trust_anchor are its common names, for display only. documents
//     are every verified document, in the response's order, each as
//     verified: for RequestDocuments, the ones the holder answered,
//     any subset of those asked for; verified is the first.
//   - "ended": no verified mdoc. reason is "declined" (the holder ended
//     the session without answering — not authenticated: anyone in
//     radio range can send that) or "error", with error, a failing
//     call's text: protocol for a response that doesn't verify.
func (p *ProximityReaderSession) HandleMessage(message []byte) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := struct {
		result
		Event     string          `json:"event"`
		Verified  *verifiedJSON   `json:"verified,omitempty"`
		Documents []*verifiedJSON `json:"documents,omitempty"`
		Send      string          `json:"send,omitempty"`
		Reason    string          `json:"reason,omitempty"`
		Error     string          `json:"error,omitempty"`
	}{result: result{ABIVersion}, Event: "ended"}
	p.stopped = true
	// No network request: the CRLs are in memory, and the status is
	// CheckStatus's.
	vs, err := p.s.VerifyDocuments(context.Background(), message, p.r.roots, p.r.clock())
	switch {
	case err == nil:
		for _, v := range vs {
			out.Documents = append(out.Documents, verifiedOf(v))
		}
		out.Event, out.Verified = "verified", out.Documents[0]
		p.verified = vs
	case errors.Is(err, proximity.ErrDeclined):
		out.Reason = "declined"
	default:
		out.Reason, out.Error = "error", revocationDetail(newError(CodeProtocol, err), err).Error()
		if status, ok := proximity.StatusFor(err); ok {
			out.Send = base64.StdEncoding.EncodeToString(proximity.StatusMessage(status))
		}
	}
	text, _ := marshal(out)
	return text
}

// verifiedOf is v as JSON.
func verifiedOf(v proximity.Verified) *verifiedJSON {
	out := &verifiedJSON{
		DocType: v.DocType, Claims: map[string]any{}, Issuer: v.IssuerCN, TrustAnchor: v.TrustAnchorCN,
		ValidFrom: v.ValidFrom.UTC().Format(time.RFC3339), ValidUntil: v.ValidUntil.UTC().Format(time.RFC3339),
		DeviceAuth: "signature",
	}
	if v.DeviceAuth == mdoc.DeviceAuthMAC {
		out.DeviceAuth = "mac"
	}
	for ns, els := range v.Claims {
		out.Claims[ns] = jsonClaims(map[string]any(els))
	}
	if len(v.DeviceSignedClaims) > 0 {
		out.DeviceSignedClaims = map[string]any{}
		for ns, els := range v.DeviceSignedClaims {
			out.DeviceSignedClaims[ns] = jsonClaims(map[string]any(els))
		}
	}
	out.Status = statusRefOf(v.Status)
	out.IssuerChain = make([]string, len(v.IssuerChain))
	for i, c := range v.IssuerChain {
		out.IssuerChain[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return out
}

// CheckStatus checks the revocation status of the mdoc HandleMessage
// verified, and returns {"abi", "status"}. It fetches the Token Status
// List the MSO names, as a CWT, and the identifier list it names
// (§12.3.6.4), and verifies each as ISO/IEC 18013-5 §12.3.6 says:
// signed under the Certificate the MSO's reference names, or else under
// the CA that signed the document signer, chaining to the root the
// document did rather than to any IACA the reader trusts. status is
// "valid", "invalid" (revoked, on either list), "suspended", another
// status the status list defines as "0x" and its value, "none" (the
// MSO names no revocation list) or "unknown" (it has a status naming no
// mechanism this reader knows): rely on the document only on "valid"
// or "none". Each list covers many documents, so fetching it doesn't
// tell its publisher which one is checked. It's fetched over
// https from public addresses only. A failed fetch is network, a list
// that doesn't verify protocol, and before a verified mdoc it's
// wrong_step. Cancelling op cancels it.
//
// With several verified documents, it checks each, and statuses are
// theirs in HandleMessage's documents order; status is then the first
// that is neither "valid" nor "none", or else "valid" if any is.
func (p *ProximityReaderSession) CheckStatus(op *Operation) (string, error) {
	p.mu.Lock()
	vs := p.verified
	p.mu.Unlock()
	if len(vs) == 0 {
		return "", newError(CodeWrongStep, errors.New("no verified mdoc to check"))
	}
	statuses := make([]string, 0, len(vs))
	for _, v := range vs {
		status, err := p.r.checkStatus(op.context(), v)
		if err != nil {
			return "", classify(err)
		}
		statuses = append(statuses, status)
	}
	return marshal(struct {
		result
		Status   string   `json:"status"`
		Statuses []string `json:"statuses"`
	}{result{ABIVersion}, combinedStatus(statuses), statuses})
}

// combinedStatus is the first of statuses that is neither "valid" nor
// "none": one document not to rely on fails them all. Otherwise it's
// "valid" when any is, else "none".
func combinedStatus(statuses []string) string {
	out := "none"
	for _, s := range statuses {
		switch s {
		case "valid":
			out = "valid"
		case "none":
		default:
			return s
		}
	}
	return out
}

// checkStatus is v's revocation status, as CheckStatus reports it.
func (r *ProximityReader) checkStatus(ctx context.Context, v proximity.Verified) (string, error) {
	switch {
	case v.Status == nil:
		return "none", nil
	case v.Status.StatusList == nil && v.Status.IdentifierList == nil:
		// A status naming no mechanism this reader knows (mdoc.Status):
		// it may still revoke the document.
		return walletflow.StatusUnknown, nil
	case len(v.IssuerChain) == 0:
		return "", errors.New("no issuer chain to bind the revocation list's signer to")
	}
	// The root the document chained to, which a list's signer must
	// chain to too unless the MSO names a Certificate.
	anchor := x509.NewCertPool()
	anchor.AddCert(v.IssuerChain[len(v.IssuerChain)-1])
	status := statuslist.StatusValid
	if ref := v.Status.StatusList; ref != nil {
		var err error
		if status, err = r.checkStatusList(ctx, ref, v.IssuerChain, anchor); err != nil {
			return "", err
		}
	}
	// Revoked on its status list, it can't be more so on an identifier
	// list.
	if ref := v.Status.IdentifierList; ref != nil && status != statuslist.StatusInvalid {
		checker := identifierlist.Checker{
			Fetcher: statusFetcher(r.identifierListMaxBytes),
			Roots:   anchor,
			Options: identifierlist.VerifyOptions{Now: r.clock, Revocation: r.statusRevocation},
			Cache:   r.statusCache,
		}
		switch err := checker.RequireNotRevoked(ctx, identifierlist.Ref(*ref), v.IssuerChain); {
		case errors.Is(err, identifierlist.ErrRevoked):
			status = statuslist.StatusInvalid
		case err != nil:
			return "", err
		}
	}
	return statusValue(status), nil
}

// checkStatusList is the document's status on the Token Status List
// ref names, its signer bound to the document's issuer (mdoc.StatusTrust)
// under anchor.
func (r *ProximityReader) checkStatusList(ctx context.Context, ref *mdoc.StatusListRef, issuerChain []*x509.Certificate, anchor *x509.CertPool) (statuslist.StatusType, error) {
	trust, err := mdoc.StatusTrust(ref, issuerChain)
	if err != nil {
		return 0, err
	}
	// The certificate the MSO names is the only root, or the signer
	// is bound to the document's issuer through trust.LeafPolicy.
	roots, signer := trust.Roots, statuslist.AnyListSigner
	if roots == nil {
		roots, signer = anchor, trust.LeafPolicy
	}
	checker := statuslist.Checker{
		Fetcher: statusFetcher(r.statusMaxBytes),
		Roots:   roots,
		Options: statuslist.VerifyOptions{
			Now: r.clock, UnboundSigner: signer, Revocation: r.statusRevocation,
			RequireExp: true, X5ChainProtectedOnly: true,
		},
		Cache: r.statusCache,
	}
	status, _, err := checker.Check(ctx, statuslist.StatusListRef{Idx: ref.Idx, URI: ref.URI}, true)
	return status, err
}

// maxStatusCacheMaxAge bounds "status_cache_max_age_seconds".
const maxStatusCacheMaxAge = 24 * time.Hour

// statusCaches keep the status and identifier lists every reader and
// Wallet in the process fetched, one Cache for each
// "status_cache_max_age_seconds", "status_cache_dir" and
// "status_cache_key" configured: a
// reader checking one issuer's documents in a queue fetches its list
// once, not per document. Each check verifies a kept list again with
// its own reader's or Wallet's trust and clock.
var statusCaches = struct {
	sync.Mutex
	byConfig map[statusCacheConfig]*statuslist.Cache
	// stores are the DirCacheStores by directory, which Caches with
	// different max ages share.
	stores map[string]*statuslist.DirCacheStore
}{byConfig: map[statusCacheConfig]*statuslist.Cache{}, stores: map[string]*statuslist.DirCacheStore{}}

type statusCacheConfig struct {
	maxAge time.Duration
	dir    string
	key    string // the store key's bytes
}

// minStatusCacheKeyBytes is the shortest "status_cache_key".
const minStatusCacheKeyBytes = 32

// statusCacheFor is the process's Cache keeping lists for maxAgeSeconds
// (zero: statuslist.DefaultCacheMaxAge), at most a day, and across
// launches in dir, when it's set (statuslist.DirCacheStore): a launch
// then revalidates each list it kept, a round trip, rather than
// downloading it. storeKey, base64, at least 32 bytes, authenticates
// what dir keeps (statuslist.CacheOptions.StoreKey).
func statusCacheFor(maxAgeSeconds int64, dir, storeKey string) (*statuslist.Cache, error) {
	if maxAgeSeconds < 0 || maxAgeSeconds > int64(maxStatusCacheMaxAge/time.Second) {
		return nil, newError(CodeInvalidInput, fmt.Errorf("status_cache_max_age_seconds is %d, not between 0 and %d", maxAgeSeconds, int64(maxStatusCacheMaxAge/time.Second)))
	}
	if dir != "" && !filepath.IsAbs(dir) {
		return nil, newError(CodeInvalidInput, fmt.Errorf("status_cache_dir %q isn't an absolute path", dir))
	}
	var keyBytes []byte
	if storeKey != "" {
		var err error
		if keyBytes, err = base64.StdEncoding.DecodeString(storeKey); err != nil || len(keyBytes) < minStatusCacheKeyBytes {
			return nil, newError(CodeInvalidInput, fmt.Errorf("status_cache_key isn't base64 of at least %d bytes", minStatusCacheKeyBytes))
		}
		if dir == "" {
			return nil, newError(CodeInvalidInput, errors.New("status_cache_key without status_cache_dir"))
		}
	}
	key := statusCacheConfig{time.Duration(maxAgeSeconds) * time.Second, filepath.Clean(dir), string(keyBytes)}
	if dir == "" {
		key.dir = ""
	}
	statusCaches.Lock()
	defer statusCaches.Unlock()
	if c, ok := statusCaches.byConfig[key]; ok {
		return c, nil
	}
	opts := statuslist.CacheOptions{MaxAge: key.maxAge, StoreKey: keyBytes}
	if key.dir != "" {
		store, ok := statusCaches.stores[key.dir]
		if !ok {
			var err error
			if store, err = statuslist.NewDirCacheStore(key.dir, 0); err != nil {
				return nil, newError(CodeInvalidInput, fmt.Errorf("status_cache_dir: %w", err))
			}
			statusCaches.stores[key.dir] = store
		}
		opts.Store = store
	}
	c := statuslist.NewCache(opts)
	statusCaches.byConfig[key] = c
	return c, nil
}

// purgeStatusCaches drops every list the process's Caches keep in
// memory.
func purgeStatusCaches() {
	statusCaches.Lock()
	defer statusCaches.Unlock()
	for _, c := range statusCaches.byConfig {
		c.Purge()
	}
}

// statusFetcher is the reader's fetcher of lists up to maxBytes (zero
// for the list's package's default): public addresses only, or with
// the mobiletest build's test client, its in-process issuer's too.
func statusFetcher(maxBytes int) statuslist.Fetcher {
	if c := testHTTP.Load(); c != nil {
		return statuslist.Fetcher{HTTP: c, AllowLoopback: true, MaxBytes: maxBytes}
	}
	return statuslist.Fetcher{MaxBytes: maxBytes}
}

// statusValue is s as walletflow names a credential's status.
func statusValue(s statuslist.StatusType) string {
	switch s {
	case statuslist.StatusValid:
		return walletflow.StatusValid
	case statuslist.StatusInvalid:
		return walletflow.StatusInvalid
	case statuslist.StatusSuspended:
		return walletflow.StatusSuspended
	}
	return fmt.Sprintf("0x%02x", uint8(s))
}

// Terminate ends the session — the reader cancelled or timed out — and
// returns {"abi", "send"}: send it (status 20) if connected, then write
// 0x02 to State and disconnect.
func (p *ProximityReaderSession) Terminate() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	text, _ := marshal(struct {
		result
		Send string `json:"send"`
	}{result{ABIVersion}, base64.StdEncoding.EncodeToString(p.s.Termination())})
	return text
}
