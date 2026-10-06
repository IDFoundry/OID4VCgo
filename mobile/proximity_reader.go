package mobile

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/proximity"
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
}

// proximityReaderConfig is NewProximityReader's configuration.
type proximityReaderConfig struct {
	// IssuerRoots are PEM certificates: the IACAs whose mdocs the
	// reader accepts.
	IssuerRoots string `json:"issuer_roots"`
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
	// with the mDL document signer extended key usage.
	RequireMDLSignerEKU bool `json:"require_mdl_signer_eku,omitempty"`
}

// NewProximityReader configures a reader from configJSON: {"abi",
// "issuer_roots", "reader_key_id", "reader_chain",
// "max_clock_skew_seconds", "require_mdl_signer_eku"}. keys holds the
// reader's key, reader_key_id; it may be nil for a reader that doesn't
// sign.
func NewProximityReader(configJSON string, keys KeyStore) (*ProximityReader, error) {
	var cfg proximityReaderConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("reader config: %w", err))
	}
	roots, err := certPool(cfg.IssuerRoots)
	if err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("issuer_roots: %w", err))
	}
	r := &ProximityReader{roots: roots, clock: time.Now}
	if cfg.MaxClockSkewSeconds != 0 {
		r.opts = append(r.opts, proximity.WithMaxClockSkew(time.Duration(cfg.MaxClockSkewSeconds)*time.Second))
	}
	if cfg.RequireMDLSignerEKU {
		r.opts = append(r.opts, proximity.WithDocumentSignerPolicy(proximity.RequireMDLDocumentSignerEKU))
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
		key, err := keyStore{keys}.load(cfg.ReaderKeyID)
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
}

type statusRefJSON struct {
	URI string `json:"uri"`
	Idx uint64 `json:"idx"`
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
//     "device_auth" ("signature" or "mac"), "status"}: claims as the
//     wallet's are (byte strings base64, dates their text). The holder
//     may withhold elements: check each one needed is there. status,
//     when present, is the MSO's status list reference ({"uri",
//     "idx"}), which isn't checked: check it before relying on the
//     document.
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
	v, err := p.s.Verify(message, p.r.roots, p.r.clock())
	switch {
	case err == nil:
		out.Event, out.Verified = "verified", verifiedOf(v)
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
	if v.Status != nil && v.Status.StatusList != nil {
		out.Status = &statusRefJSON{URI: v.Status.StatusList.URI, Idx: v.Status.StatusList.Idx}
	}
	return out
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
