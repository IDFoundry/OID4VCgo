package mobile

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
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
}

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
// "reader_chain", "max_clock_skew_seconds", "require_mdl_signer_eku",
// "accept_mdl_signer_without_eku", "crls", "crl_issuers", "revocation"},
// refusing any other key, so a misspelled option isn't silently left
// at its default. keys holds the reader's key, reader_key_id; it may be
// nil for a reader that doesn't sign.
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
	// Development assurance, with any IACA in issuer_roots for any
	// document type: issuer_roots_by_doctype decides which issue which.
	// The documents' status is CheckStatus's, a call of its own:
	// HandleMessage, which runs no network request, checks none.
	r.opts = append(r.opts, proximity.WithAssurance(verifier.AssuranceDevelopment), proximity.WithAnyIssuerForAnyType(), proximity.WithNoStatusCheck())
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

// configureRevocation sets the revocation check of each role cfg's
// "revocation" names, over cfg's "crls".
func (r *ProximityReader) configureRevocation(cfg proximityReaderConfig) error {
	named, err := revocationRoles("revocation", cfg.Revocation, revocationIssuer, revocationStatus)
	if err != nil {
		return err
	}
	if r.crls, err = newCRLSet(cfg.CRLs, cfg.CRLIssuers); err != nil {
		return err
	}
	var issuer certrevocation.Checker = certrevocation.NoCheck{}
	if named[revocationIssuer] {
		issuer = r.crls.checker()
	}
	r.opts = append(r.opts, proximity.WithIssuerRevocation(issuer))
	if named[revocationStatus] {
		r.statusRevocation = r.crls.checker()
	}
	return nil
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
	// verified is the mdoc HandleMessage verified, for CheckStatus.
	verified *proximity.Verified
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
// "signed"}. ble_mode is the mode the reader uses, from those the holder
// offers (central client mode when it offers both, §8.3.3.1.1):
//   - "peripheral_server": the holder advertises service_uuid and is
//     the GATT server; the reader scans, connects, and is the GATT
//     client.
//   - "central_client": the reader advertises service_uuid and is the
//     GATT server, serving ident (base64) on the Ident characteristic;
//     the holder connects.
//
// signed is whether the request will carry reader authentication.
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
	}{result{ABIVersion}, p.s.ServiceUUID(), mode, base64.StdEncoding.EncodeToString(p.s.BLEIdent()), p.r.readerCN != ""})
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
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.asked || p.stopped {
		return "", newError(CodeWrongStep, errors.New("the request was already sent"))
	}
	msg, err := p.s.Establishment(docType, elements)
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
}

// statusRefOf is an MSO's status reference as JSON: either mechanism,
// or one it doesn't know, so a document revoked through an identifier
// list, or through another mechanism, doesn't look like one with no
// status at all.
func statusRefOf(status *mdoc.Status) *statusRefJSON {
	switch {
	case status == nil:
		return nil
	case status.StatusList != nil:
		return &statusRefJSON{
			Type: "status_list", URI: status.StatusList.URI, Idx: status.StatusList.Idx,
			Certificate: base64.StdEncoding.EncodeToString(status.StatusList.Certificate),
		}
	case status.IdentifierList != nil:
		return &statusRefJSON{
			Type: "identifier_list", URI: status.IdentifierList.URI,
			ID:          base64.StdEncoding.EncodeToString(status.IdentifierList.ID),
			Certificate: base64.StdEncoding.EncodeToString(status.IdentifierList.Certificate),
		}
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
//     trust_anchor are its common names, for display only.
//   - "ended": no verified mdoc. reason is "declined" (the holder ended
//     the session without answering — not authenticated: anyone in
//     radio range can send that) or "error", with error, a failing
//     call's text: protocol for a response that doesn't verify.
func (p *ProximityReaderSession) HandleMessage(message []byte) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := struct {
		result
		Event    string        `json:"event"`
		Verified *verifiedJSON `json:"verified,omitempty"`
		Send     string        `json:"send,omitempty"`
		Reason   string        `json:"reason,omitempty"`
		Error    string        `json:"error,omitempty"`
	}{result: result{ABIVersion}, Event: "ended"}
	p.stopped = true
	// No network request: the CRLs are in memory, and the status is
	// CheckStatus's.
	v, err := p.s.Verify(context.Background(), message, p.r.roots, p.r.clock())
	switch {
	case err == nil:
		out.Event, out.Verified = "verified", verifiedOf(v)
		p.verified = &v
	case errors.Is(err, proximity.ErrDeclined):
		out.Reason = "declined"
	default:
		out.Reason, out.Error = "error", newError(CodeProtocol, err).Error()
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
// List the MSO names, as a CWT, and verifies it as ISO/IEC 18013-5
// §12.3.6 says: signed under the Certificate the MSO's status names,
// or else under the CA that signed the document signer, chaining to
// the root the document did rather than to any IACA the reader trusts.
// status is "valid", "invalid" (revoked), "suspended", another status
// the list defines as "0x" and its value, "none" (the MSO names no
// revocation list) or "unknown" (it names an identifier list,
// §12.3.6.3, which this reader can't check, and either no status list
// or one on which it's valid; or it has a status naming no mechanism
// this reader knows): rely on the document only on "valid" or
// "none". The list covers many documents, so fetching it
// doesn't tell its publisher which one is checked. It's fetched over
// https from public addresses only. A failed fetch is network, a list
// that doesn't verify protocol, and before a verified mdoc it's
// wrong_step. Cancelling op cancels it.
func (p *ProximityReaderSession) CheckStatus(op *Operation) (string, error) {
	p.mu.Lock()
	v := p.verified
	p.mu.Unlock()
	if v == nil {
		return "", newError(CodeWrongStep, errors.New("no verified mdoc to check"))
	}
	status, err := p.r.checkStatus(op.context(), *v)
	if err != nil {
		return "", classify(err)
	}
	return marshal(struct {
		result
		Status string `json:"status"`
	}{result{ABIVersion}, status})
}

// checkStatus is v's revocation status, as CheckStatus reports it.
func (r *ProximityReader) checkStatus(ctx context.Context, v proximity.Verified) (string, error) {
	switch {
	case v.Status == nil:
		return "none", nil
	case v.Status.StatusList == nil:
		// An identifier list, or a status naming no mechanism this
		// reader knows (mdoc.Status): either may revoke the document.
		return walletflow.StatusUnknown, nil
	case len(v.IssuerChain) == 0:
		return "", errors.New("no issuer chain to bind the status list's signer to")
	}
	ref := v.Status.StatusList
	trust, err := mdoc.StatusTrust(ref, v.IssuerChain)
	if err != nil {
		return "", err
	}
	roots := trust.Roots
	if roots == nil {
		roots = x509.NewCertPool()
		roots.AddCert(v.IssuerChain[len(v.IssuerChain)-1])
	}
	checker := statuslist.Checker{
		Fetcher: statusFetcher(),
		Roots:   roots,
		Options: statuslist.VerifyOptions{
			Now: r.clock, LeafPolicy: trust.LeafPolicy, Revocation: r.statusRevocation,
			RequireExp: true, X5ChainProtectedOnly: true,
		},
	}
	status, _, err := checker.Check(ctx, statuslist.StatusListRef{Idx: ref.Idx, URI: ref.URI}, true)
	if err != nil {
		return "", err
	}
	if status == statuslist.StatusValid && v.Status.IdentifierList != nil {
		// Valid on the status list, but the identifier list the MSO
		// names too, which this reader can't check, may still revoke it.
		return walletflow.StatusUnknown, nil
	}
	return statusValue(status), nil
}

// statusFetcher is the reader's status list fetcher: public addresses
// only, or with the mobiletest build's test client, its in-process
// issuer's too.
func statusFetcher() statuslist.Fetcher {
	if c := testHTTP.Load(); c != nil {
		return statuslist.Fetcher{HTTP: c, AllowLoopback: true}
	}
	return statuslist.Fetcher{}
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
