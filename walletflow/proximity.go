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
	w *Wallet
	s *proximity.DeviceSession

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

// StartProximityPresentation starts a session in mdoc peripheral server
// mode: the holder's device advertises ServiceUUID and is the GATT
// server, after showing QRCode.
func (w *Wallet) StartProximityPresentation() (*ProximityPresentation, error) {
	s, err := proximity.NewDeviceSession(w.deps.Random)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return &ProximityPresentation{w: w, s: s, byID: map[string]StoredCredential{}}, nil
}

// QRCode is the device engagement to show, "mdoc:" and its base64url
// (§8.2.2.3).
func (p *ProximityPresentation) QRCode() string { return p.s.QRCode() }

// ServiceUUID is the BLE service UUID to advertise.
func (p *ProximityPresentation) ServiceUUID() string { return p.s.ServiceUUID() }

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
	// One document per response: the first request is the one shown.
	p.reqs = reqs
	p.reader = p.s.VerifyReaderAuth(reqs[0], proximity.ReaderTrust{
		Roots: p.w.cfg.MdocReaderRoots, LeafPolicy: p.w.cfg.MdocReaderLeafPolicy, Now: p.w.deps.Clock(),
	})
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
// sent: the holder can try again, or Terminate.
func (p *ProximityPresentation) Respond(ctx context.Context, request int, credentialID string, elements [][2]string) (ProximityPresented, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != proximityRequested {
		return ProximityPresented{}, ErrWrongStep
	}
	if err := p.checkSelection(request, credentialID, elements); err != nil {
		return ProximityPresented{}, err
	}
	reserved, err := p.w.reserve(ctx, Selection{"": {credentialID}}, p.verifier, p.linkable)
	if err != nil {
		return ProximityPresented{}, err
	}
	send, err := p.respond(ctx, request, reserved[0], elements)
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
	resp, err := proximity.BuildDeviceResponse(p.reqs[request], issuerSigned, k, p.s.SessionTranscriptBytes(), elements)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	send, err := p.s.Encrypt(resp, true)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return send, nil
}

// Terminate ends the session — the holder declined, cancelled or timed
// out — and returns the message telling the reader so (status 20),
// for the app to send if a reader is connected. Nothing is disclosed.
func (p *ProximityPresentation) Terminate() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = proximityEnded
	return p.s.Termination()
}
