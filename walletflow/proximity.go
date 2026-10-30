package walletflow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/proximity"
)

// ErrReaderEnded is a ProximityEvent's Err when the reader ended the
// session before the holder answered: its status 20, or a status
// reporting an error in what the holder sent.
var ErrReaderEnded = errors.New("walletflow: the reader ended the session")

// ProximityPresentation is one ISO/IEC 18013-5 in-person presentation
// from the holder's side (package proximity): the holder shows QRCode,
// a reader scans it and connects over BLE, and the app hands each whole
// message the reader sends to HandleMessage, and sends whatever comes
// back. The radio transport is the app's. One request per session: the
// holder answers it with Respond, or ends the session with Terminate.
type ProximityPresentation struct {
	w        *Wallet
	s        *proximity.DeviceSession
	combined *proximity.CombinedDeviceSession

	// terminating is set by Terminate before it waits for mu, so a
	// Respond holding mu — waiting on a holder key's prompt — sees it
	// and gives nothing to send.
	terminating atomic.Bool

	mu       sync.Mutex
	state    proximityState
	reqs     []proximity.DocRequest
	reader   proximity.ReaderAuthentication
	requests []MdocRequest
	byID     map[string]StoredCredential
	// verifierName is the reader's name among Verifiers (verifierID),
	// verifier its VerifierHash.
	verifierName, verifier string
}

type proximityState int

const (
	proximityWaiting   proximityState = iota // for the reader's SessionEstablishment
	proximityRequested                       // a request, for the holder's consent
	proximityEnded
)

// StartProximityPresentation starts a session offering modes, mdoc
// peripheral server mode alone without any. After showing QRCode, the
// holder's device, in peripheral server mode, advertises
// PeripheralServerUUID and is the GATT server; in central client mode,
// it scans for CentralClientUUID and connects as GATT client, checking
// the reader's Ident characteristic against BLEIdent. Offering both, it
// does both until the reader connects one way.
func (w *Wallet) StartProximityPresentation(modes ...proximity.BLEMode) (*ProximityPresentation, error) {
	return w.startProximityPresentation(proximity.NewDeviceSession, modes...)
}

// StartNFCProximityPresentation starts a static NFC handover to BLE.
// The platform exposes HandoverSelect through its Type 4 tag service
// and retains this presentation across repeated NFC reads. Consent,
// reader trust and response handling are identical to QR presentation.
func (w *Wallet) StartNFCProximityPresentation(modes ...proximity.BLEMode) (*ProximityPresentation, error) {
	return w.startProximityPresentation(proximity.NewNFCDeviceSession, modes...)
}

// StartNFCNegotiatedProximityPresentation prepares a negotiated NFC
// engagement. Pass the complete Hr to HandleHandoverRequest before
// starting the BLE transport selected by its response.
func (w *Wallet) StartNFCNegotiatedProximityPresentation(modes ...proximity.BLEMode) (*ProximityPresentation, error) {
	return w.startProximityPresentation(proximity.NewNFCNegotiatedDeviceSession, modes...)
}

// StartNFCDataProximityPresentation starts static NFC engagement with classic
// NFC-only retrieval. Native code implements APDU I/O; consent remains here.
func (w *Wallet) StartNFCDataProximityPresentation(parameters proximity.NFCDataParameters) (*ProximityPresentation, error) {
	return w.startProximityPresentation(func(random io.Reader, _ ...proximity.DeviceOption) (*proximity.DeviceSession, error) {
		return proximity.NewNFCDataDeviceSession(random, parameters)
	})
}

// StartNFCNegotiatedDataProximityPresentation negotiates classic NFC-only retrieval.
func (w *Wallet) StartNFCNegotiatedDataProximityPresentation(parameters proximity.NFCDataParameters) (*ProximityPresentation, error) {
	return w.startProximityPresentation(func(random io.Reader, _ ...proximity.DeviceOption) (*proximity.DeviceSession, error) {
		return proximity.NewNFCNegotiatedDataDeviceSession(random, parameters)
	})
}

func (w *Wallet) startProximityPresentation(create func(io.Reader, ...proximity.DeviceOption) (*proximity.DeviceSession, error), modes ...proximity.BLEMode) (*ProximityPresentation, error) {
	var opts []proximity.DeviceOption
	if len(modes) > 0 {
		opts = append(opts, proximity.WithBLEModes(modes...))
	}
	s, err := create(w.deps.Random, opts...)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return &ProximityPresentation{w: w, s: s, byID: map[string]StoredCredential{}}, nil
}

// QRCode is the device engagement to show, "mdoc:" and its base64url
// (§8.2.2.3).
func (p *ProximityPresentation) QRCode() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.combined != nil {
		if q := p.combined.QROffer(); q != nil {
			return q.QRCode()
		}
		return ""
	}
	return p.s.QRCode()
}

// HandoverSelect is the static NFC NDEF message, without NLEN; nil for
// QR sessions. The returned copy may be passed to platform NFC code.
func (p *ProximityPresentation) HandoverSelect() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.combined != nil {
		return p.combined.NFCOffer().HandoverSelect()
	}
	return p.s.HandoverSelect()
}

// ProximityEngagement is an atomic snapshot of the presentation's transport
// settings. Negotiated selection must not mix UUIDs from different states.
type ProximityEngagement struct {
	QRCode               string
	PeripheralServerUUID string
	CentralClientUUID    string
	BLEIdent             []byte
}

// Engagement returns a transport snapshot safe to read during Hr selection.
func (p *ProximityPresentation) Engagement() ProximityEngagement {
	p.mu.Lock()
	defer p.mu.Unlock()
	// With no QR offer, carrier metadata belongs only to NFC and must not
	// start a QR transport before NFC selection and the complete Hs read.
	if p.combined != nil && p.combined.SelectedEngagement() == "" && p.combined.QROffer() == nil {
		return ProximityEngagement{}
	}
	return ProximityEngagement{QRCode: p.s.QRCode(), PeripheralServerUUID: p.s.PeripheralServerUUID(), CentralClientUUID: p.s.CentralClientUUID(), BLEIdent: append([]byte(nil), p.s.BLEIdent()...)}
}

// HandleHandoverRequest selects the negotiated carrier while the
// presentation is waiting. In a combined presentation this prepares the NFC
// offer without claiming it or changing the QR offer. It does not start a radio.
func (p *ProximityPresentation) HandleHandoverRequest(hr []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != proximityWaiting {
		return nil, fmt.Errorf("walletflow: no NFC handover pending: %w", proximity.ErrSessionClosed)
	}
	if p.combined != nil {
		if p.combined.SelectedEngagement() == "qr" {
			return nil, fmt.Errorf("walletflow: QR already selected: %w", proximity.ErrSessionClosed)
		}
		return p.combined.NFCOffer().HandleHandoverRequest(hr)
	}
	return p.s.HandleHandoverRequest(hr)
}

// ServiceUUID is the BLE service UUID: PeripheralServerUUID when the
// session offers that mode, else CentralClientUUID.
func (p *ProximityPresentation) ServiceUUID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.s.ServiceUUID()
}

// PeripheralServerUUID is the service UUID to advertise in mdoc
// peripheral server mode; empty when the session doesn't offer it.
func (p *ProximityPresentation) PeripheralServerUUID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.s.PeripheralServerUUID()
}

// CentralClientUUID is the service UUID to scan for and connect to in
// mdoc central client mode; empty when the session doesn't offer it.
func (p *ProximityPresentation) CentralClientUUID() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.s.CentralClientUUID()
}

// BLEIdent is the value the reader's Ident characteristic must hold in
// mdoc central client mode: disconnect from a reader whose differs.
func (p *ProximityPresentation) BLEIdent() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.s.BLEIdent()...)
}

// ProximityEvent is what HandleMessage made of a message.
type ProximityEvent struct {
	// Send is a message for the app to send the reader, when not nil.
	Send []byte
	// Request is true when a request is ready for the holder's
	// consent: Reader and Requests describe it.
	Request bool
	// Ended is true when the session is over: after Send, if any, the
	// app disconnects.
	Ended bool
	// Err is why an Ended session ended without an answer: an error
	// wrapping ErrReaderEnded, ErrUntrustedVerifier (a reader
	// Config.RequireTrustedMdocReader refuses), or the bad message's
	// error from package proximity. nil while the session goes on.
	Err error
}

// HandleMessage processes a whole message from the reader. The first
// is its SessionEstablishment, carrying the request: the event's
// Request is then true, unless the request was refused. Later ones end
// the session.
func (p *ProximityPresentation) HandleMessage(ctx context.Context, msg []byte) ProximityEvent {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch p.state {
	case proximityWaiting:
		if p.combined != nil && p.combined.SelectedEngagement() == "" {
			return ProximityEvent{Err: fmt.Errorf("walletflow: engagement not selected: %w", proximity.ErrSessionClosed)}
		}
		return p.establish(ctx, msg)
	case proximityRequested:
		// A message before the holder answered: the reader ending the
		// session, or a second request, which this wallet doesn't take.
		_, status, err := p.s.HandleSessionData(msg)
		return p.endAfter(status, err)
	default:
		return ProximityEvent{Ended: true, Err: fmt.Errorf("walletflow: %w", proximity.ErrSessionClosed)}
	}
}

// establish handles the SessionEstablishment.
func (p *ProximityPresentation) establish(ctx context.Context, msg []byte) ProximityEvent {
	reqBytes, err := p.s.HandleSessionEstablishment(msg)
	if err != nil {
		return p.fail(err)
	}
	reqs, err := proximity.ParseDeviceRequest(reqBytes)
	if err != nil {
		p.state = proximityEnded
		send, encErr := p.s.ErrorResponse(err)
		if encErr != nil {
			send = p.s.Termination()
		}
		return ProximityEvent{Send: send, Ended: true, Err: fmt.Errorf("walletflow: %w", err)}
	}
	p.reqs = reqs
	// The holder may answer any of the requests, so each one's
	// readerAuth counts, not only the first's.
	p.reader = p.readerOf(reqs)
	if p.w.cfg.RequireTrustedMdocReader && p.reader.Status != proximity.ReaderTrusted {
		p.state = proximityEnded
		return ProximityEvent{Send: p.s.Termination(), Ended: true, Err: fmt.Errorf("walletflow: %w: %w", ErrUntrustedVerifier, p.reader.Err)}
	}
	if p.verifierName, err = p.verifierID(); err != nil {
		p.state = proximityEnded
		return ProximityEvent{Send: p.s.Termination(), Ended: true, Err: err}
	}
	p.verifier = VerifierHash(p.verifierName)
	stored, err := p.w.deps.Credentials.List(ctx)
	if err != nil {
		p.state = proximityEnded
		return ProximityEvent{Send: p.s.Termination(), Ended: true, Err: fmt.Errorf("walletflow: list credentials: %w", err)}
	}
	for _, d := range reqs {
		r := MdocRequest{DocType: d.DocType}
		for _, e := range d.Elements {
			r.Elements = append(r.Elements, MdocElement{Namespace: e[0], Identifier: e[1], Retain: d.IntentToRetain[e]})
		}
		for _, c := range stored {
			if c.Format == mdoc.CredentialFormat && c.DocType == d.DocType {
				r.Credentials = append(r.Credentials, c)
				p.byID[c.ID] = c
			}
		}
		p.requests = append(p.requests, r)
	}
	p.state = proximityRequested
	return ProximityEvent{Request: true}
}

// fail ends the session after a message the holder couldn't process,
// sending the status reply proximity.StatusFor gives, if any.
func (p *ProximityPresentation) fail(err error) ProximityEvent {
	p.state = proximityEnded
	ev := ProximityEvent{Ended: true, Err: fmt.Errorf("walletflow: %w", err)}
	if status, ok := proximity.StatusFor(err); ok {
		ev.Send = proximity.StatusMessage(status)
	}
	return ev
}

// endAfter ends the session after a SessionData that came before the
// holder answered.
func (p *ProximityPresentation) endAfter(status *uint64, err error) ProximityEvent {
	if err != nil {
		return p.fail(err)
	}
	p.state = proximityEnded
	if status != nil {
		return ProximityEvent{Ended: true, Err: fmt.Errorf("%w (status %d)", ErrReaderEnded, *status)}
	}
	// A second request: one per session.
	return ProximityEvent{Send: p.s.Termination(), Ended: true, Err: fmt.Errorf("%w: it sent a second request", ErrReaderEnded)}
}

// verifierID names the reader among the Verifiers credential copies
// were shown to (hashed, as VerifierHash): by its certificate, when its
// signature verifies, else as a reader seen only in this session.
func (p *ProximityPresentation) verifierID() (string, error) {
	switch p.reader.Status {
	case proximity.ReaderTrusted, proximity.ReaderUntrusted:
		sum := sha256.Sum256(p.reader.Chain[0].Raw)
		return "mdoc-reader:" + base64.RawURLEncoding.EncodeToString(sum[:]), nil
	default:
		b := make([]byte, 16)
		if _, err := io.ReadFull(p.w.deps.Random, b); err != nil {
			return "", fmt.Errorf("walletflow: %w", err)
		}
		return "mdoc-reader-session:" + hex.EncodeToString(b), nil
	}
}

// readerOf is who sent reqs: trusted only when every DocRequest is
// signed by the same trusted reader, as mdocdcapi requires too.
// Otherwise it's the weakest request's result (invalid, then
// unauthenticated, then untrusted): a reader can't attach an unsigned
// or untrusted request for one document to a trusted one for another
// and have the wallet show the trusted name for both.
func (p *ProximityPresentation) readerOf(reqs []proximity.DocRequest) proximity.ReaderAuthentication {
	trust := proximity.ReaderTrust{
		Roots: p.w.cfg.MdocReaderRoots, LeafPolicy: p.w.cfg.MdocReaderLeafPolicy, Revocation: p.w.cfg.MdocReaderRevocation, Now: p.w.deps.Clock(),
	}
	weakness := map[proximity.ReaderStatus]int{
		proximity.ReaderTrusted: 0, proximity.ReaderUntrusted: 1, proximity.ReaderUnauthenticated: 2, proximity.ReaderInvalid: 3,
	}
	var reader proximity.ReaderAuthentication
	for i, req := range reqs {
		got := p.s.VerifyReaderAuth(req, trust)
		if i > 0 && got.Status == proximity.ReaderTrusted && reader.Status == proximity.ReaderTrusted && !got.Chain[0].Equal(reader.Chain[0]) {
			got = proximity.ReaderAuthentication{Status: proximity.ReaderUntrusted, Chain: got.Chain, Err: errors.New("the documents are signed by different readers")}
		}
		if i == 0 || weakness[got.Status] > weakness[reader.Status] {
			reader = got
		}
	}
	return reader
}

// Reader is who sent the request: its readerAuth's status and
// certificate chain (proximity.VerifyReaderAuth), under
// Config.MdocReaderRoots and MdocReaderLeafPolicy. Only a
// proximity.ReaderTrusted chain is the reader's verified identity.
func (p *ProximityPresentation) Reader() proximity.ReaderAuthentication {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reader
}

// Requests are the requested documents, in the request's order, each
// with its elements in the request's order.
func (p *ProximityPresentation) Requests() []MdocRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests
}

// Linkable reports whether presenting the credential id names to this
// reader now would hand it a copy another Verifier has seen.
func (p *ProximityPresentation) Linkable(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.linkable(id)
}

// ShownTo reports whether the credential id names has been shown to
// this reader before: one whose signature verified, by the same
// certificate. A reader that didn't sign is never known.
func (p *ProximityPresentation) ShownTo(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.byID[id]
	return ok && p.verifierName != "" && c.ShownTo(p.verifierName)
}

func (p *ProximityPresentation) linkable(id string) bool {
	c, ok := p.byID[id]
	return ok && p.w.linkable(c, p.verifier)
}

// ProximityPresented is Respond's answer.
type ProximityPresented struct {
	// Send is the message to send the reader: the encrypted
	// DeviceResponse, ending the session. The app then disconnects.
	Send []byte
	// Linkable is whether the copy presented had been seen by another
	// Verifier.
	Linkable bool
}

// Respond presents the held mdoc credentialID for request number
// request, disclosing exactly elements — each a [namespace, identifier]
// the request asked for (ErrInvalidSelection otherwise) — with the
// credential's next unused copy, its holder key signing over the
// session transcript, and ends the session. A KeyStore that requires
// user presence prompts now. On an error the session goes on, nothing
// sent: the holder can try again, or Terminate. Terminate called before
// Respond returns — while the holder key prompts, say — wins: Respond
// fails with ErrTerminated, releasing the copy, and gives no message.
// Once Respond has returned, the app checks it hasn't ended the session
// itself before it sends Send.
func (p *ProximityPresentation) Respond(ctx context.Context, request int, credentialID string, elements [][2]string) (ProximityPresented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != proximityRequested {
		return ProximityPresented{}, ErrWrongStep
	}
	if p.terminating.Load() {
		return ProximityPresented{}, ErrTerminated
	}
	if err := p.checkSelection(request, credentialID, elements); err != nil {
		return ProximityPresented{}, err
	}
	reserved, err := p.w.reserve(ctx, Selection{"": {credentialID}}, p.verifier, p.linkable, p.byID)
	if err != nil {
		return ProximityPresented{}, err
	}
	send, err := p.respond(ctx, request, reserved[0], elements)
	if err == nil && p.terminating.Load() {
		// Terminate came while the holder key signed: the session is
		// over, and the response is dropped.
		err = ErrTerminated
	}
	if err != nil {
		// Nothing left the wallet: the copy wasn't seen.
		p.w.release(ctx, reserved, p.verifier)
		return ProximityPresented{}, err
	}
	p.state = proximityEnded
	return ProximityPresented{Send: send, Linkable: reserved[0].linkable}, nil
}

// checkSelection refuses a request, credential or elements Respond
// can't present.
func (p *ProximityPresentation) checkSelection(request int, credentialID string, elements [][2]string) error {
	if request < 0 || request >= len(p.requests) {
		return fmt.Errorf("walletflow: %w: no document request %d", ErrInvalidSelection, request)
	}
	if c, ok := p.byID[credentialID]; !ok || c.DocType != p.requests[request].DocType {
		return fmt.Errorf("walletflow: %w: credential %q doesn't answer document request %d", ErrInvalidSelection, credentialID, request)
	}
	if len(elements) == 0 {
		return fmt.Errorf("walletflow: %w: no element to disclose", ErrInvalidSelection)
	}
	for _, e := range elements {
		requested := false
		for _, r := range p.reqs[request].Elements {
			requested = requested || r == e
		}
		if !requested {
			return fmt.Errorf("walletflow: %w: %s/%s wasn't requested", ErrInvalidSelection, e[0], e[1])
		}
	}
	return nil
}

// respond builds the encrypted DeviceResponse with the reserved copy.
func (p *ProximityPresentation) respond(ctx context.Context, request int, r reservedCopy, elements [][2]string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(r.c.Credential)
	if err != nil {
		return nil, fmt.Errorf("walletflow: credential %q: %w", r.id, err)
	}
	issuerSigned, err := mdoc.UnmarshalIssuerSigned(raw)
	if err != nil {
		return nil, fmt.Errorf("walletflow: credential %q: %w", r.id, err)
	}
	k, err := p.w.deps.Keys.Key(ctx, r.keyID)
	if err != nil {
		return nil, fmt.Errorf("walletflow: credential %q's holder key: %w", r.id, err)
	}
	resp, err := p.deviceResponse(request, issuerSigned, k, elements)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	send, err := p.s.Encrypt(resp, true)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return send, nil
}

// deviceResponse builds the DeviceResponse, authenticating the mdoc as
// Config.ProximityDeviceAuth says: with ProximityDeviceMACPreferred and
// a holder key that agrees keys (proximity.KeyAgreer), with a MAC;
// otherwise, or if the key can't agree (proximity.ErrNoKeyAgreement),
// with a signature.
func (p *ProximityPresentation) deviceResponse(request int, issuerSigned mdoc.IssuerSigned, k Key, elements [][2]string) ([]byte, error) {
	if ka, ok := k.(proximity.KeyAgreer); ok && p.w.cfg.ProximityDeviceAuth == ProximityDeviceMACPreferred {
		resp, err := proximity.BuildDeviceResponseMAC(p.reqs[request], issuerSigned, ka, p.s.EReaderKey(), p.s.SessionTranscriptBytes(), elements)
		if !errors.Is(err, proximity.ErrNoKeyAgreement) {
			return resp, err
		}
	}
	return proximity.BuildDeviceResponse(p.reqs[request], issuerSigned, k, p.s.SessionTranscriptBytes(), elements)
}

// ProximityDeviceAuth is how an in-person response authenticates the
// mdoc (ISO/IEC 18013-5 §9.1.3).
type ProximityDeviceAuth int

const (
	// ProximityDeviceSignature signs over the session transcript with
	// the holder key (deviceSignature).
	ProximityDeviceSignature ProximityDeviceAuth = iota
	// ProximityDeviceMACPreferred MACs the session transcript under a
	// key the holder key agrees with the reader's ephemeral key
	// (deviceMac), when the holder key is a proximity.KeyAgreer that
	// can; otherwise it signs. Unlike a signature, the reader can't
	// show anyone else the holder made the response.
	ProximityDeviceMACPreferred
)

// Terminate ends the session — the holder declined, cancelled or timed
// out — and returns the message telling the reader so (status 20),
// for the app to send if a reader is connected. Nothing is disclosed:
// a Respond still running fails with ErrTerminated.
func (p *ProximityPresentation) Terminate() []byte {
	p.terminating.Store(true)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = proximityEnded
	if p.combined != nil {
		p.combined.Close()
	}
	return p.s.Termination()
}
