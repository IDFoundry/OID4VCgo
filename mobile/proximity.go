package mobile

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// ProximityPresentation is one ISO/IEC 18013-5 in-person presentation
// from the holder's side (walletflow.ProximityPresentation): the holder
// shows the QR code, a reader scans it and connects over BLE, and the
// app hands each whole message from the reader to HandleMessage and
// sends what comes back. The BLE transport is the app's: in mdoc
// peripheral server mode, the holder's device advertises the service
// UUID and is the GATT server. Its methods are safe to call from any
// thread.
type ProximityPresentation struct {
	p *walletflow.ProximityPresentation
}

// StartProximityPresentation starts a session, generating its
// ephemeral key and service UUID.
func (w *Wallet) StartProximityPresentation() (*ProximityPresentation, error) {
	p, err := w.w.StartProximityPresentation()
	if err != nil {
		return nil, classify(err)
	}
	return &ProximityPresentation{p: p}, nil
}

// Engagement returns {"abi", "qr_code", "service_uuid", "ble_mode"}:
// the QR code's text ("mdoc:" and the DeviceEngagement), the BLE
// service UUID to advertise, and "peripheral_server", the mode.
func (p *ProximityPresentation) Engagement() string {
	text, _ := marshal(struct {
		result
		QRCode      string `json:"qr_code"`
		ServiceUUID string `json:"service_uuid"`
		BLEMode     string `json:"ble_mode"`
	}{result{ABIVersion}, p.p.QRCode(), p.p.ServiceUUID(), "peripheral_server"})
	return text
}

// proximityEventJSON is HandleMessage's result.
type proximityEventJSON struct {
	result
	// Event is "request" (Request describes it), "ended" or "none".
	Event string `json:"event"`
	// Send is the base64 message to send the reader, if any.
	Send string `json:"send,omitempty"`
	// Reason is why the session ended: "reader_ended", or "error".
	Reason string `json:"reason,omitempty"`
	// Error is the error, as a failing call's text, for "error".
	Error string `json:"error,omitempty"`
}

// HandleMessage processes one whole message from the reader,
// reassembled from its BLE chunks, and returns {"abi", "event", "send",
// "reason", "error"}. Send "send", base64, when present. event is:
//   - "request": the reader's request is ready for the holder's
//     consent — show Request, then Respond or Terminate;
//   - "ended": the session is over — disconnect after sending "send".
//     reason is "reader_ended" (the reader ended it first) or "error"
//     (a bad message, or a reader require_trusted_mdoc_reader
//     refuses), with error, a failing call's text;
//   - "none": nothing to do.
func (p *ProximityPresentation) HandleMessage(op *Operation, message []byte) string {
	ev := p.p.HandleMessage(op.context(), message)
	out := proximityEventJSON{result: result{ABIVersion}, Event: "none"}
	if ev.Send != nil {
		out.Send = base64.StdEncoding.EncodeToString(ev.Send)
	}
	switch {
	case ev.Request:
		out.Event = "request"
	case ev.Ended:
		out.Event = "ended"
		if errors.Is(ev.Err, walletflow.ErrReaderEnded) {
			out.Reason = "reader_ended"
		} else if ev.Err != nil {
			out.Reason, out.Error = "error", classify(ev.Err).Error()
		}
	}
	text, _ := marshal(out)
	return text
}

type proximityReaderJSON struct {
	Status       string            `json:"status"`
	Name         string            `json:"name"`
	Chain        []string          `json:"chain"`
	Certificates []certificateJSON `json:"certificates"`
	Error        string            `json:"error,omitempty"`
}

// certificateJSON is a certificate's fields, for an app to show where
// the platform can't parse one (iOS).
type certificateJSON struct {
	Subject           string   `json:"subject"`
	Issuer            string   `json:"issuer"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	Serial            string   `json:"serial"`
	SubjectAltNames   []string `json:"subject_alt_names"`
	ExtendedKeyUsages []string `json:"extended_key_usages"`
	KeyUsages         []string `json:"key_usages"`
	IsCA              bool     `json:"is_ca"`
	SignatureAlg      string   `json:"signature_algorithm"`
	Extensions        []string `json:"extensions"`
	SHA256            string   `json:"sha256"`
}

func certificateOf(c *x509.Certificate) certificateJSON {
	out := certificateJSON{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		Serial: c.SerialNumber.Text(16), IsCA: c.IsCA, SignatureAlg: c.SignatureAlgorithm.String(),
		SubjectAltNames:   append(append(append([]string{}, c.DNSNames...), c.EmailAddresses...), ipStrings(c)...),
		ExtendedKeyUsages: []string{}, KeyUsages: []string{}, Extensions: []string{},
	}
	for _, u := range c.URIs {
		out.SubjectAltNames = append(out.SubjectAltNames, u.String())
	}
	for _, eku := range c.ExtKeyUsage {
		out.ExtendedKeyUsages = append(out.ExtendedKeyUsages, extKeyUsageNames[eku])
	}
	for _, eku := range c.UnknownExtKeyUsage {
		name := eku.String()
		if eku.Equal(proximity.ReaderAuthenticationEKU) {
			name = "mdoc reader authentication (" + name + ")"
		}
		out.ExtendedKeyUsages = append(out.ExtendedKeyUsages, name)
	}
	for i, name := range keyUsageNames {
		if c.KeyUsage&(1<<i) != 0 {
			out.KeyUsages = append(out.KeyUsages, name)
		}
	}
	for _, e := range c.Extensions {
		name := e.Id.String()
		if e.Critical {
			name += " (critical)"
		}
		out.Extensions = append(out.Extensions, name)
	}
	sum := sha256.Sum256(c.Raw)
	out.SHA256 = strings.ToUpper(hex.EncodeToString(sum[:]))
	return out
}

func ipStrings(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// keyUsageNames are x509.KeyUsage's bits, in order.
var keyUsageNames = []string{"digitalSignature", "contentCommitment", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"}

var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "serverAuth", x509.ExtKeyUsageClientAuth: "clientAuth",
	x509.ExtKeyUsageCodeSigning: "codeSigning", x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping: "timeStamping", x509.ExtKeyUsageOCSPSigning: "OCSPSigning",
}

// Request returns the reader's request, for the holder's consent:
// {"abi", "reader": {"status", "name", "chain", "error"}, "documents":
// [{"doctype", "elements": [{"namespace", "identifier", "retain"}],
// "credentials": [summary]}]}, the documents and elements in the
// request's order. reader.status is "trusted" (its certificate chains
// to mdoc_reader_roots), "untrusted" (signed, by a certificate that
// doesn't), "unauthenticated" (not signed) or "invalid" (a signature
// that doesn't verify for this session); name is the certificate's
// subject common name — the reader's verified name only when
// "trusted" — and chain its certificates, leaf first, base64 DER, with
// certificates their fields, for an app that can't parse them: {"subject",
// "issuer", "not_before", "not_after", "serial" (hex),
// "subject_alt_names", "extended_key_usages", "key_usages", "is_ca",
// "signature_algorithm", "extensions" (OIDs), "sha256" (hex)}.
// Each summary has shown_to_verifier and linkable_here for this reader.
// Before the "request" event, documents is empty.
func (p *ProximityPresentation) Request() string {
	r := p.p.Reader()
	reader := proximityReaderJSON{Status: r.Status.String(), Chain: []string{}, Certificates: []certificateJSON{}}
	for _, c := range r.Chain {
		reader.Chain = append(reader.Chain, base64.StdEncoding.EncodeToString(c.Raw))
		reader.Certificates = append(reader.Certificates, certificateOf(c))
	}
	if len(r.Chain) > 0 {
		reader.Name = r.Chain[0].Subject.CommonName
	}
	if r.Err != nil {
		reader.Error = cleanText(r.Err.Error())
	}
	out := struct {
		result
		Reader    proximityReaderJSON `json:"reader"`
		Documents []mdocDocumentJSON  `json:"documents"`
	}{result: result{ABIVersion}, Reader: reader, Documents: []mdocDocumentJSON{}}
	for _, req := range p.p.Requests() {
		d := mdocDocumentJSON{DocType: req.DocType, Elements: []mdocElementJSON{}, Credentials: []credentialSummary{}}
		for _, e := range req.Elements {
			d.Elements = append(d.Elements, mdocElementJSON{e.Namespace, e.Identifier, e.Retain})
		}
		for _, c := range req.Credentials {
			s := summaryOf(c)
			shown, linkable := p.p.ShownTo(c.ID), p.p.Linkable(c.ID)
			s.ShownToVerifier, s.LinkableHere = &shown, &linkable
			d.Credentials = append(d.Credentials, s)
		}
		out.Documents = append(out.Documents, d)
	}
	text, _ := marshal(out)
	return text
}

// Respond presents the held mdoc credentialID for document number
// document, disclosing exactly elementsJSON — a JSON array of
// [namespace, identifier] pairs, each one the document requested
// (invalid_selection otherwise) — and returns {"abi", "send",
// "linkable"}: send the base64 "send", the encrypted response, which
// ends the session, then disconnect. The holder key signs here, so a
// KeyStore requiring user presence prompts now. On an error nothing is
// sent and the session goes on: try again, or Terminate.
func (p *ProximityPresentation) Respond(op *Operation, document int, credentialID, elementsJSON string) (string, error) {
	var elements [][2]string
	if err := json.Unmarshal([]byte(elementsJSON), &elements); err != nil {
		return "", newError(CodeInvalidInput, fmt.Errorf("elements: %w", err))
	}
	presented, err := p.p.Respond(op.context(), document, credentialID, elements)
	if err != nil {
		return "", classify(err)
	}
	return marshal(struct {
		result
		Send     string `json:"send"`
		Linkable bool   `json:"linkable"`
	}{result{ABIVersion}, base64.StdEncoding.EncodeToString(presented.Send), presented.Linkable})
}

// Terminate ends the session — the holder declined, cancelled, or a
// timeout passed — and returns {"abi", "send"}: send it if a reader is
// connected (status 20), then disconnect. Nothing is disclosed.
func (p *ProximityPresentation) Terminate() string {
	text, _ := marshal(struct {
		result
		Send string `json:"send"`
	}{result{ABIVersion}, base64.StdEncoding.EncodeToString(p.p.Terminate())})
	return text
}
