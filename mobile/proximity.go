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

	"github.com/idfoundry/oid4vcgo/internal/displaytext"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// ProximityPresentation is one ISO/IEC 18013-5 in-person presentation
// from the holder's side (walletflow.ProximityPresentation): the holder
// shows the QR code, a reader scans it and connects over BLE, and the
// app hands each whole message from the reader to HandleMessage and
// sends what comes back. The BLE transport is the app's: in mdoc
// peripheral server mode, the holder's device advertises the service
// UUID and is the GATT server; in mdoc central client mode, it scans
// for the reader's and connects as GATT client. Its methods are safe to
// call from any thread.
type ProximityPresentation struct {
	p *walletflow.ProximityPresentation
}

// StartProximityPresentation starts a session in mdoc peripheral server
// mode, generating its ephemeral key and service UUID.
func (w *Wallet) StartProximityPresentation() (*ProximityPresentation, error) {
	return w.StartProximityPresentationWithModes(`["peripheral_server"]`)
}

// StartProximityPresentationWithModes starts a session offering the BLE
// modes modesJSON lists: "peripheral_server", "central_client", or
// both, each with its own service UUID (Engagement's ble_modes).
// Offering both, the app advertises and scans until the reader connects
// one way; a reader offered both should choose central client mode.
func (w *Wallet) StartProximityPresentationWithModes(modesJSON string) (*ProximityPresentation, error) {
	return w.startProximityPresentationWithModes(modesJSON, w.w.StartProximityPresentation)
}

// StartNFCProximityPresentationWithModes starts a static NFC handover
// to BLE. modesJSON has the same shape as StartProximityPresentationWithModes.
// Expose HandoverSelect as the Type 4 NDEF message (without NLEN), retain
// the handle through the BLE transaction, and use the existing consent
// and response methods. This does not register a platform HCE service.
func (w *Wallet) StartNFCProximityPresentationWithModes(modesJSON string) (*ProximityPresentation, error) {
	return w.startProximityPresentationWithModes(modesJSON, w.w.StartNFCProximityPresentation)
}

func parseProximityModes(modesJSON string) ([]proximity.BLEMode, error) {
	var names []string
	if err := json.Unmarshal([]byte(modesJSON), &names); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("modes: %w", err))
	}
	if len(names) == 0 {
		return nil, newError(CodeInvalidInput, errors.New("modes: none given"))
	}
	modes := make([]proximity.BLEMode, 0, len(names))
	for _, n := range names {
		switch n {
		case "peripheral_server":
			modes = append(modes, proximity.PeripheralServer)
		case "central_client":
			modes = append(modes, proximity.CentralClient)
		default:
			return nil, newError(CodeInvalidInput, fmt.Errorf("modes: %q isn't peripheral_server or central_client", cleanText(n)))
		}
	}
	return modes, nil
}

func (w *Wallet) startProximityPresentationWithModes(modesJSON string, start func(...proximity.BLEMode) (*walletflow.ProximityPresentation, error)) (*ProximityPresentation, error) {
	modes, err := parseProximityModes(modesJSON)
	if err != nil {
		return nil, err
	}
	p, err := start(modes...)
	if err != nil {
		return nil, classify(err)
	}
	return &ProximityPresentation{p: p}, nil
}

// HandoverSelect returns a copy of the static NFC NDEF message without
// its Type 4 NLEN prefix, or nil for a QR presentation. A platform must
// reuse these bytes rather than starting a new presentation per read.
func (p *ProximityPresentation) HandoverSelect() []byte { return p.p.HandoverSelect() }

type bleModeJSON struct {
	Mode        string `json:"mode"`
	ServiceUUID string `json:"service_uuid"`
}

// Engagement returns {"abi", "qr_code", "service_uuid", "ble_mode",
// "ble_modes", "ident"}: the QR code's text ("mdoc:" and the
// DeviceEngagement), and each mode offered in ble_modes, with its
// service UUID:
//   - "peripheral_server": advertise service_uuid and be the GATT
//     server;
//   - "central_client": scan for service_uuid, connect as GATT client,
//     and disconnect from a reader whose Ident characteristic isn't
//     ident (base64).
//
// service_uuid and ble_mode are ble_modes' first, peripheral server
// mode's when offered.
func (p *ProximityPresentation) Engagement() string {
	engagement := p.p.Engagement()
	modes := []bleModeJSON{}
	if u := engagement.PeripheralServerUUID; u != "" {
		modes = append(modes, bleModeJSON{"peripheral_server", u})
	}
	ident := ""
	if u := engagement.CentralClientUUID; u != "" {
		modes = append(modes, bleModeJSON{"central_client", u})
		ident = base64.StdEncoding.EncodeToString(engagement.BLEIdent)
	}
	first := bleModeJSON{}
	if len(modes) > 0 {
		first = modes[0]
	}
	text, _ := marshal(struct {
		result
		QRCode      string        `json:"qr_code"`
		ServiceUUID string        `json:"service_uuid"`
		BLEMode     string        `json:"ble_mode"`
		BLEModes    []bleModeJSON `json:"ble_modes"`
		Ident       string        `json:"ident,omitempty"`
	}{result{ABIVersion}, engagement.QRCode, first.ServiceUUID, first.Mode, modes, ident})
	return text
}

// proximityEventJSON is HandleMessage's result.
type proximityEventJSON struct {
	result
	// Event is "request" (Request describes it), "ended", "rejected"
	// or "none".
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
//   - "rejected": the session's first message didn't decode or decrypt
//     for this engagement, so its sender never saw the engagement and
//     isn't the reader. Nothing is sent: drop the device that sent it,
//     and hand the next first message, from any device, to
//     HandleMessage. The session waits on, however many arrive: the
//     request timeout bounds the wait (added within ABI 15);
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
	case ev.Rejected:
		out.Event = "rejected"
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
	ClaimedName  string            `json:"claimed_name,omitempty"`
	Chain        []string          `json:"chain"`
	Certificates []certificateJSON `json:"certificates"`
	Error        string            `json:"error,omitempty"`
	// ErrorDetail is DetailCertificateRevoked or DetailNoCurrentCRL when
	// Error comes from checking the reader's certificate chain for
	// revocation (mdoc_reader in "revocation").
	ErrorDetail string `json:"error_detail,omitempty"`
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

// certificateOf is c's fields for certificateJSON. The names in it —
// subject, issuer, subject alternative names — are
// whatever the certificate's maker wrote, trusted or not: each is
// cleaned as displayName cleans a name (certificateText), so none can
// carry control, line separator or bidirectional characters to a
// screen.
func certificateOf(c *x509.Certificate) certificateJSON {
	out := certificateJSON{
		Subject: certificateText(c.Subject.String()), Issuer: certificateText(c.Issuer.String()),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		Serial: c.SerialNumber.Text(16), IsCA: c.IsCA, SignatureAlg: c.SignatureAlgorithm.String(),
		SubjectAltNames:   []string{},
		ExtendedKeyUsages: []string{}, KeyUsages: []string{}, Extensions: []string{},
	}
	names := append(append(append([]string{}, c.DNSNames...), c.EmailAddresses...), ipStrings(c)...)
	for _, u := range c.URIs {
		names = append(names, u.String())
	}
	for _, n := range names {
		out.SubjectAltNames = append(out.SubjectAltNames, certificateText(n))
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
// that doesn't verify for this session), with error why it isn't
// trusted, and error_detail "certificate_revoked" or "no_current_crl"
// (DetailCertificateRevoked, DetailNoCurrentCRL) when that's its
// certificate's revocation check; name is the certificate's
// subject common name — the reader's verified name only when
// "trusted" — and chain its certificates, leaf first, base64 DER, with
// certificates their fields, for an app that can't parse them: {"subject",
// "issuer", "not_before", "not_after", "serial" (hex),
// "subject_alt_names", "extended_key_usages", "key_usages", "is_ca",
// "signature_algorithm", "extensions" (OIDs), "sha256" (hex)}.
// Each summary has shown_to_verifier and linkable_here for this reader.
// Before the "request" event, documents is empty.
//
// request_info is the request's second-edition information, or null:
// before the "request" event, after a refused request, and when the
// reader sent none. Otherwise it is {"use_cases": [{"mandatory",
// "document_sets", "purpose_hints"}], "signed"}: each use case's
// mandatory flag, its document sets — arrays of indices into documents
// — and its purpose hints, an object from controller ID to integer
// purpose code (signed 32-bit), all as the reader sent them; empty
// arrays and objects stay empty, never null. signed is true only when
// a verified whole-request signature (readerAuthAll) covers it, every
// signature the request carries having verified; it is not reader
// trust, which is reader.status, and neither shows that a purpose is
// true or that the reader may ask for it.
//
// Each document also has request_info: its document request's
// information, or null when the reader sent none or it couldn't be
// read. Otherwise it is {"alternative_data_elements":
// [{"requested_element": {"namespace", "identifier"},
// "alternative_element_sets": [[{"namespace", "identifier"}]]}],
// "issuer_identifiers": [base64]}: for one of the document's elements,
// the alternatives the reader accepts in its place, most preferred
// first, each a set of elements together; and the issuers it accepts,
// each an authority key identifier's KeyIdentifier, all as the reader
// sent them, empty arrays never null. Nothing in it is enforced, and
// Respond still discloses only the document's elements.
func (p *ProximityPresentation) Request() string {
	r := p.p.Reader()
	reader := proximityReaderJSON{Status: r.Status.String(), Chain: []string{}, Certificates: []certificateJSON{}}
	for _, c := range r.Chain {
		reader.Chain = append(reader.Chain, base64.StdEncoding.EncodeToString(c.Raw))
		reader.Certificates = append(reader.Certificates, certificateOf(c))
	}
	// A name only for a reader its certificate vouches for: anyone can
	// put a public chain, or a certificate naming any authority, on a
	// garbage signature. Another's name is only what it claims.
	if len(r.Chain) > 0 {
		cn := displayName(r.Chain[0].Subject.CommonName)
		if r.Status == proximity.ReaderTrusted {
			reader.Name = cn
		} else {
			reader.ClaimedName = cn
		}
	}
	if r.Err != nil {
		reader.Error, reader.ErrorDetail = cleanText(r.Err.Error()), revocationCause(r.Err)
	}
	out := struct {
		result
		Reader      proximityReaderJSON     `json:"reader"`
		Documents   []proximityDocumentJSON `json:"documents"`
		RequestInfo *requestInfoJSON        `json:"request_info"`
	}{result: result{ABIVersion}, Reader: reader, Documents: []proximityDocumentJSON{}, RequestInfo: requestInfoOf(p.p.RequestInfo())}
	for _, req := range p.p.Requests() {
		d := proximityDocumentJSON{
			mdocDocumentJSON: mdocDocumentJSON{DocType: req.DocType, Elements: []mdocElementJSON{}, Credentials: []credentialSummary{}},
			RequestInfo:      docRequestInfoOf(req.RequestInfo),
		}
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

// proximityDocumentJSON is one of Request's documents: an
// org-iso-mdoc request's, with its request_info.
type proximityDocumentJSON struct {
	mdocDocumentJSON
	RequestInfo *docRequestInfoJSON `json:"request_info"`
}

// docRequestInfoJSON is a document's request_info.
type docRequestInfoJSON struct {
	AlternativeDataElements []alternativeDataElementsJSON `json:"alternative_data_elements"`
	IssuerIdentifiers       []string                      `json:"issuer_identifiers"`
}

type alternativeDataElementsJSON struct {
	RequestedElement       elementReferenceJSON     `json:"requested_element"`
	AlternativeElementSets [][]elementReferenceJSON `json:"alternative_element_sets"`
}

type elementReferenceJSON struct {
	Namespace  string `json:"namespace"`
	Identifier string `json:"identifier"`
}

// docRequestInfoOf is info as a document's request_info: nil for nil,
// and every collection non-nil.
func docRequestInfoOf(info *proximity.DocRequestInfo) *docRequestInfoJSON {
	if info == nil {
		return nil
	}
	out := &docRequestInfoJSON{AlternativeDataElements: make([]alternativeDataElementsJSON, 0, len(info.AlternativeDataElements)), IssuerIdentifiers: make([]string, 0, len(info.IssuerIdentifiers))}
	for _, set := range info.AlternativeDataElements {
		a := alternativeDataElementsJSON{
			RequestedElement:       elementReferenceJSON{set.RequestedElement[0], set.RequestedElement[1]},
			AlternativeElementSets: make([][]elementReferenceJSON, 0, len(set.AlternativeElementSets)),
		}
		for _, alt := range set.AlternativeElementSets {
			refs := make([]elementReferenceJSON, 0, len(alt))
			for _, e := range alt {
				refs = append(refs, elementReferenceJSON{e[0], e[1]})
			}
			a.AlternativeElementSets = append(a.AlternativeElementSets, refs)
		}
		out.AlternativeDataElements = append(out.AlternativeDataElements, a)
	}
	for _, id := range info.IssuerIdentifiers {
		out.IssuerIdentifiers = append(out.IssuerIdentifiers, base64.StdEncoding.EncodeToString(id))
	}
	return out
}

// requestInfoJSON is Request's request_info.
type requestInfoJSON struct {
	UseCases []useCaseJSON `json:"use_cases"`
	Signed   bool          `json:"signed"`
}

type useCaseJSON struct {
	Mandatory    bool             `json:"mandatory"`
	DocumentSets [][]int          `json:"document_sets"`
	PurposeHints map[string]int32 `json:"purpose_hints"`
}

// requestInfoOf is info as request_info: nil for nil, and every
// collection non-nil, so none is encoded as null.
func requestInfoOf(info *proximity.RequestInfo) *requestInfoJSON {
	if info == nil {
		return nil
	}
	out := &requestInfoJSON{UseCases: make([]useCaseJSON, 0, len(info.UseCases)), Signed: info.Signed}
	for _, uc := range info.UseCases {
		c := useCaseJSON{Mandatory: uc.Mandatory, DocumentSets: make([][]int, 0, len(uc.DocumentSets)), PurposeHints: map[string]int32{}}
		for _, set := range uc.DocumentSets {
			c.DocumentSets = append(c.DocumentSets, append(make([]int, 0, len(set)), set...))
		}
		for id, code := range uc.PurposeHints {
			c.PurposeHints[id] = code
		}
		out.UseCases = append(out.UseCases, c)
	}
	return out
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
	elements, err := mdocElementsJSON(elementsJSON)
	if err != nil {
		return "", err
	}
	presented, err := p.p.Respond(op.context(), document, credentialID, elements)
	if err != nil {
		return "", classify(err)
	}
	return proximityPresentedJSON(presented)
}

// RespondDocuments presents several of the request's documents in one
// DeviceResponse (walletflow.ProximityPresentation.RespondDocuments):
// answersJSON is a JSON array of {"document", "credential_id",
// "elements"}, each as Respond's arguments, at least one, no document
// twice and no credential twice (invalid_selection otherwise). A
// document left out isn't in the response. It returns Respond's {"abi",
// "send", "linkable", "linkable_credentials"}: linkable whether any
// copy presented had been seen by another Verifier,
// linkable_credentials which, by credential ID. Each holder key signs
// here, in the request's order, so each KeyStore requiring user
// presence prompts in turn. On an error — one prompt cancelled, say —
// nothing is sent, the keys after it aren't asked, and the session
// goes on: try again, or Terminate.
func (p *ProximityPresentation) RespondDocuments(op *Operation, answersJSON string) (string, error) {
	answers, err := mdocAnswers(answersJSON)
	if err != nil {
		return "", err
	}
	presented, err := p.p.RespondDocuments(op.context(), answers)
	if err != nil {
		return "", classify(err)
	}
	return proximityPresentedJSON(presented)
}

func proximityPresentedJSON(presented walletflow.ProximityPresented) (string, error) {
	return marshal(struct {
		result
		Send                string   `json:"send"`
		Linkable            bool     `json:"linkable"`
		LinkableCredentials []string `json:"linkable_credentials"`
	}{result{ABIVersion}, base64.StdEncoding.EncodeToString(presented.Send), presented.Linkable, nonNil(presented.LinkableCredentials)})
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

// displayName is a certificate's name fit for the holder's screen, as
// walletflow fits an issuer's or Verifier's (displaytext.Clean): no
// control, line separator or invisible format characters, at most 200
// runes.
func displayName(s string) string { return displaytext.Clean(s, 200) }

// certificateText is a certificate's distinguished name or alternative
// name, cleaned as displayName is, but allowed a longer one: at most
// 1,024 runes.
func certificateText(s string) string { return displaytext.Clean(s, 1024) }
