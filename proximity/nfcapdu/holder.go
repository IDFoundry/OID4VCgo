package nfcapdu

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/proximity"
)

// HolderOptions configures a Holder.
type HolderOptions struct {
	// HandoverSelect is the static Handover Select message the tag
	// serves. Leave it nil when Negotiate is set.
	HandoverSelect []byte
	// Negotiate, when set, makes the tag serve TNEP negotiated handover:
	// it is given the reader's complete Handover Request and returns the
	// Handover Select.
	Negotiate func(hr []byte) (hs []byte, err error)
	// Data offers NFC data retrieval after the handover, with the APDU
	// data-field limits the Handover Select advertises. They must fit
	// short APDUs: a command of at most 255 bytes, a response of at most
	// 256.
	Data bool
}

// Step is what a Holder did with one command APDU.
type Step struct {
	// Response is the response APDU to send, or nil when Message is set:
	// then the response follows from Respond.
	Response []byte
	// HandoverRead reports the reader has just read the complete
	// Handover Select. The native app commits the NFC engagement then
	// (for BLE retrieval; NFC data retrieval commits on DataSelected).
	HandoverRead bool
	// DataSelected reports the reader has selected the NFC data
	// application.
	DataSelected bool
	// Message is a complete session message from the reader, for the
	// session, which answers it with Respond.
	Message []byte
	// Delivered reports the reader has read the last of the response to
	// its last message.
	Delivered bool
}

// Deactivation is what a Holder did when the NFC field was lost.
type Deactivation struct {
	// Cancel reports a negotiated handover was answered but its Handover
	// Select not read in full: the session it froze can't be resumed,
	// so the presentation ends.
	Cancel bool
	// DataClosed reports NFC data retrieval was in progress and has
	// ended; the session's transport is gone.
	DataClosed bool
}

// Holder is the mdoc's side of NFC engagement and retrieval: a Type 4
// Tag serving the handover, by static or TNEP negotiated handover, and
// optionally the NFC data application. It is safe for concurrent use,
// though the native app passes it one command APDU at a time.
type Holder struct {
	mu           sync.Mutex
	tag          *type4Tag
	tnep         *tnepHolder
	data         *dataHolder
	dataSelected bool
}

// NewHolder returns a Holder serving opts' handover.
func NewHolder(opts HolderOptions) (*Holder, error) {
	h := &Holder{}
	if opts.Data {
		h.data = &dataHolder{}
	}
	initial := opts.HandoverSelect
	var update func([]byte) ([]byte, error)
	switch {
	case opts.Negotiate != nil && opts.HandoverSelect != nil:
		return nil, errors.New("nfcapdu: a negotiated handover has no static Handover Select")
	case opts.Negotiate != nil:
		h.tnep = &tnepHolder{negotiate: func(hr []byte) ([]byte, error) {
			hs, err := opts.Negotiate(hr)
			if err == nil && h.data != nil {
				err = h.data.useParameters(hs)
			}
			return hs, err
		}}
		initial, update = tnepParameters, h.tnep.transact
	case opts.Data:
		if err := h.data.useParameters(opts.HandoverSelect); err != nil {
			return nil, err
		}
	}
	tag, err := newType4Tag(initial, update)
	if err != nil {
		return nil, err
	}
	h.tag = tag
	return h, nil
}

// Process answers one command APDU.
func (h *Holder) Process(apdu []byte) Step {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := ParseCommand(apdu); ok && c.isSelectByName() {
		h.dataSelected = h.data != nil && bytes.Equal(c.Data, DataApplication)
	}
	if h.dataSelected {
		return h.data.process(apdu)
	}
	resp, read := h.tag.process(apdu)
	return Step{Response: resp, HandoverRead: read && (h.tnep == nil || h.tnep.handoverReady)}
}

// Respond answers the pending session message with message, returning
// the response APDU to send for it: its first part, when it needs GET
// RESPONSE for the rest.
func (h *Holder) Respond(message []byte) (Step, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.data == nil {
		return Step{}, errors.New("nfcapdu: no NFC data retrieval")
	}
	return h.data.respond(message)
}

// RefuseMessage drops the pending session message, which the session
// couldn't take, returning the response APDU that refuses it.
func (h *Holder) RefuseMessage() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.data != nil {
		h.data.pending = false
	}
	return response(swConditionsNotMet, nil)
}

// Deactivate handles the loss of the NFC field. handoverCommitted reports
// the native app committed this NFC engagement; qrSelected that a QR
// engagement won instead, so nothing here may end the presentation.
func (h *Holder) Deactivate(handoverCommitted, qrSelected bool) Deactivation {
	h.mu.Lock()
	defer h.mu.Unlock()
	var d Deactivation
	if qrSelected {
		h.tag.deactivate(nil)
		h.dataSelected = false
		return d
	}
	switch {
	case h.tnep != nil && !handoverCommitted && h.tnep.handoverReady:
		d.Cancel = true
		h.tag.deactivate(nil)
	case h.tnep != nil && !handoverCommitted:
		h.tnep.selected = false
		h.tag.deactivate(tnepParameters)
	default:
		h.tag.deactivate(nil)
	}
	if h.dataSelected && h.data.selected && !h.data.closed {
		h.data.close()
		d.DataClosed = true
	}
	h.dataSelected = false
	return d
}

// Close ends NFC data retrieval: later commands for it are refused.
func (h *Holder) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.data != nil {
		h.data.close()
	}
}

// dataHolder is the NFC data application (§8.3.3.1.2): it reassembles
// the reader's ENVELOPE chain into a session message, and returns the
// answer through the final ENVELOPE's response and GET RESPONSE.
type dataHolder struct {
	maxCommand, maxResponse int
	selected, closed        bool
	chain                   []byte
	pending                 bool // a message awaits Respond
	le                      int  // the final ENVELOPE's Le
	outgoing                []byte
	offset                  int
}

// useParameters takes the APDU data-field limits hs advertises.
func (d *dataHolder) useParameters(hs []byte) error {
	if d.selected {
		return errors.New("nfcapdu: NFC data application already selected")
	}
	p, err := proximity.ParseNFCDataHandover(hs)
	if err != nil {
		return err
	}
	if p.MaxCommand < 1 || p.MaxCommand > 255 || p.MaxResponse < 1 || p.MaxResponse > 256 {
		return fmt.Errorf("nfcapdu: NFC data limits %d/%d need extended APDUs", p.MaxCommand, p.MaxResponse)
	}
	d.maxCommand, d.maxResponse = p.MaxCommand, p.MaxResponse
	return nil
}

func (d *dataHolder) process(apdu []byte) Step {
	if d.closed {
		return Step{Response: response(swConditionsNotMet, nil)}
	}
	c, ok := ParseCommand(apdu)
	if !ok {
		return Step{Response: response(swWrongLength, nil)}
	}
	if c.INS == insSelect {
		// ISO/IEC 18013-5 §11.2 (Table 8) selects with P2 0x0C and no
		// Le; some readers ask with P2 0. Either way the answer carries
		// no data (Table 9).
		if !c.isSelectByName() || !bytes.Equal(c.Data, DataApplication) {
			return Step{Response: response(swFileNotFound, nil)}
		}
		if len(d.chain) != 0 || d.pending || d.outgoing != nil {
			return Step{Response: response(swConditionsNotMet, nil)}
		}
		d.selected = true
		return Step{Response: response(swOK, nil), DataSelected: true}
	}
	if !d.selected {
		return Step{Response: response(swConditionsNotMet, nil)}
	}
	if c.P1 != 0 || c.P2 != 0 {
		return Step{Response: response(swWrongP1P2, nil)}
	}
	switch c.INS {
	case insEnvelope:
		return d.envelope(c)
	case insGetResponse:
		if c.CLA != 0 || len(c.Data) != 0 || c.Le < 1 || c.Le > d.maxResponse {
			return Step{Response: response(swWrongP1P2, nil)}
		}
		if d.outgoing == nil {
			return Step{Response: response(swConditionsNotMet, nil)}
		}
		return d.next(c.Le)
	}
	return Step{Response: response(swINSNotSupported, nil)}
}

func (d *dataHolder) envelope(c Command) Step {
	chained := c.CLA == 0x10
	if c.CLA != 0 && !chained {
		return Step{Response: response(swCLANotSupported, nil)}
	}
	if d.pending || d.outgoing != nil {
		return Step{Response: response(swConditionsNotMet, nil)}
	}
	if len(c.Data) == 0 || len(c.Data) > d.maxCommand || len(d.chain)+len(c.Data) > maxEncoded {
		d.chain = nil
		return Step{Response: response(swWrongLength, nil)}
	}
	if chained && c.Le != 0 || !chained && (c.Le < 1 || c.Le > d.maxResponse) {
		return Step{Response: response(swWrongP1P2, nil)}
	}
	d.chain = append(d.chain, c.Data...)
	if chained {
		return Step{Response: response(swOK, nil)}
	}
	message, err := UnwrapDO53(d.chain)
	d.chain = nil
	if err != nil {
		return Step{Response: response(swWrongData, nil)}
	}
	d.le = c.Le
	d.pending = true
	return Step{Message: message}
}

func (d *dataHolder) respond(message []byte) (Step, error) {
	if d.closed || d.outgoing != nil || !d.pending {
		return Step{}, errors.New("nfcapdu: no NFC message awaits a response")
	}
	encoded, err := WrapDO53(message)
	if err != nil {
		return Step{}, err
	}
	d.outgoing, d.offset, d.pending = encoded, 0, false
	return d.next(d.le), nil
}

// next returns the next part of the outgoing response, of at most
// maximum bytes, with 61XX while more remains (XX the bytes left, or 00
// for 256 or more).
func (d *dataHolder) next(maximum int) Step {
	end := min(d.offset+maximum, len(d.outgoing))
	chunk := d.outgoing[d.offset:end]
	d.offset = end
	remaining := len(d.outgoing) - end
	if remaining == 0 {
		d.outgoing = nil
		return Step{Response: response(swOK, chunk), Delivered: true}
	}
	if remaining >= 256 {
		remaining = 0
	}
	return Step{Response: response(swMoreData|remaining, chunk)}
}

func (d *dataHolder) close() {
	d.closed = true
	d.pending = false
	d.outgoing = nil
	d.chain = nil
}
