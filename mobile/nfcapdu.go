package mobile

import (
	"sync"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/proximity/nfcapdu"
)

// What a command APDU selects, from ClassifyNFCCommand.
const (
	NFCCommandOther           = int(nfcapdu.CommandOther)
	NFCCommandSelectNDEF      = int(nfcapdu.CommandSelectNDEF)
	NFCCommandSelectData      = int(nfcapdu.CommandSelectData)
	NFCCommandSelectDataNoFCI = int(nfcapdu.CommandSelectDataNoFCI)
	NFCCommandSelectOther     = int(nfcapdu.CommandSelectOther)
)

// ClassifyNFCCommand reports which application, if any, a command APDU
// selects: one of the NFCCommand constants.
func ClassifyNFCCommand(apdu []byte) int { return int(nfcapdu.Classify(apdu)) }

// NFCHolder is the mdoc's NFC tag for one presentation: it serves the
// handover and, with NFC data retrieval, the session's messages, one
// command APDU at a time.
type NFCHolder struct{ h *nfcapdu.Holder }

// NFCStep is what NFCHolder did with one command APDU.
type NFCStep struct {
	// Response is the response APDU; nil when Message is set.
	Response []byte
	// HandoverRead: the reader has read the whole Handover Select.
	HandoverRead bool
	// DataSelected: the reader has selected the NFC data application.
	DataSelected bool
	// HasMessage: Message holds a session message from the reader,
	// answered with NFCHolder.Respond.
	HasMessage bool
	Message    []byte
	// Delivered: the reader has read the last of the answer.
	Delivered bool
}

// NFCDeactivation is what NFCHolder did when the NFC field was lost.
type NFCDeactivation struct {
	// Cancel: a negotiated handover was answered but not read; end the
	// presentation.
	Cancel bool
	// DataClosed: NFC data retrieval was in progress and has ended.
	DataClosed bool
}

// NFCHolder returns the NFC tag serving this presentation's handover:
// TNEP negotiated when negotiated is set, static otherwise, and NFC data
// retrieval when nfcData is set.
func (p *ProximityPresentation) NFCHolder(negotiated, nfcData bool) (*NFCHolder, error) {
	opts := nfcapdu.HolderOptions{Data: nfcData}
	if negotiated {
		opts.Negotiate = p.p.HandleHandoverRequest
	} else {
		opts.HandoverSelect = p.p.HandoverSelect()
	}
	h, err := nfcapdu.NewHolder(opts)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &NFCHolder{h: h}, nil
}

// Process answers one command APDU.
func (h *NFCHolder) Process(apdu []byte) *NFCStep { return nfcStep(h.h.Process(apdu)) }

// Respond answers the pending session message, returning the response
// APDU for it.
func (h *NFCHolder) Respond(message []byte) (*NFCStep, error) {
	step, err := h.h.Respond(message)
	if err != nil {
		return nil, newError(CodeWrongStep, err)
	}
	return nfcStep(step), nil
}

// RefuseMessage drops the pending session message, returning the
// response APDU refusing it.
func (h *NFCHolder) RefuseMessage() []byte { return h.h.RefuseMessage() }

// Deactivate handles field loss. handoverCommitted: the app committed
// this NFC engagement; qrSelected: a QR engagement won instead.
func (h *NFCHolder) Deactivate(handoverCommitted, qrSelected bool) *NFCDeactivation {
	d := h.h.Deactivate(handoverCommitted, qrSelected)
	return &NFCDeactivation{Cancel: d.Cancel, DataClosed: d.DataClosed}
}

// Close ends NFC data retrieval.
func (h *NFCHolder) Close() { h.h.Close() }

func nfcStep(s nfcapdu.Step) *NFCStep {
	return &NFCStep{Response: s.Response, HandoverRead: s.HandoverRead, DataSelected: s.DataSelected, HasMessage: s.Message != nil, Message: s.Message, Delivered: s.Delivered}
}

// NFCExchange is a reader's sequence of command APDUs: send Command after
// waiting WaitMillis, pass the response to Next, and repeat until
// Command is nil; Result is then the outcome. Its methods are safe to
// call from any thread: each waits for one in progress, except Close,
// which ends a Next waiting on the sequence. Until it's done, the
// sequence holds a goroutine, so Close an exchange abandoned before
// then: the tag lost, or the reader cancelled.
type NFCExchange struct {
	mu         sync.Mutex
	e          *nfcapdu.Exchange
	negotiated func() bool
}

// NewNFCHandoverRead reads an mdoc's Handover Select over a tag
// connection whose longest APDU is maxTransceive bytes, sending hr if the
// mdoc offers negotiated handover (refused when hr is nil).
func NewNFCHandoverRead(maxTransceive int, hr []byte) *NFCExchange {
	r := nfcapdu.ReadHandover(maxTransceive, hr)
	return &NFCExchange{e: r.Exchange, negotiated: r.Negotiated}
}

// NewNFCTransact sends one session message to an mdoc's NFC data
// application and reads its answer, within maxTransceive and the
// APDU data-field limits its Handover Select advertises.
func NewNFCTransact(maxTransceive, maxCommand, maxResponse int, message []byte) *NFCExchange {
	p := proximity.NFCDataParameters{MaxCommand: maxCommand, MaxResponse: maxResponse}
	return &NFCExchange{e: nfcapdu.Transact(maxTransceive, p, message)}
}

// Done reports the exchange is over: Result holds its outcome.
func (x *NFCExchange) Done() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.e.Command() == nil
}

// Command is the next command APDU, or nil when the exchange is over.
func (x *NFCExchange) Command() []byte {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.e.Command()
}

// WaitMillis is how long to wait before sending Command.
func (x *NFCExchange) WaitMillis() int64 {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.e.Wait().Milliseconds()
}

// Next passes the response to Command.
func (x *NFCExchange) Next(response []byte) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if err := x.e.Next(response); err != nil {
		return newError(CodeWrongStep, err)
	}
	return nil
}

// Result is the outcome once Command is nil: the Handover Select read,
// or the mdoc's answer.
func (x *NFCExchange) Result() ([]byte, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	b, err := x.e.Result()
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return b, nil
}

// Negotiated reports, after NewNFCHandoverRead's exchange, that the mdoc
// used TNEP negotiated handover: the reader session binds hr too.
func (x *NFCExchange) Negotiated() bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.negotiated != nil && x.negotiated()
}

// Close abandons the exchange, ending a Next in progress: it doesn't
// wait for the lock the other methods take, which that Next holds.
func (x *NFCExchange) Close() { x.e.Close() }

// NFCSelectDataApplication is the command selecting an mdoc's NFC data
// application.
func NFCSelectDataApplication() []byte { return nfcapdu.SelectDataApplication() }

// CheckNFCDataApplicationSelected checks the response to
// NFCSelectDataApplication.
func CheckNFCDataApplicationSelected(response []byte) error {
	if err := nfcapdu.CheckDataApplicationSelected(response); err != nil {
		return newError(CodeInvalidInput, err)
	}
	return nil
}
