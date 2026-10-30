package nfcapdu

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
)

// errExchangeClosed ends an Exchange's sequence when it is closed.
var errExchangeClosed = errors.New("nfcapdu: exchange closed")

// An Exchange is a sequence of command APDUs to send to the tag, each
// depending on the responses before it. Send Command, after waiting
// Wait, pass its response to Next, and repeat until Command is nil; then
// Result holds the outcome. Close an Exchange abandoned before then:
// until its sequence is over, it holds a goroutine. An Exchange isn't
// safe for concurrent use, except that Close may be called from any
// goroutine, ending a Next waiting on the sequence.
type Exchange struct {
	steps     chan exchangeStep
	responses chan []byte
	quit      chan struct{}
	closeOnce sync.Once
	current   exchangeStep
}

type exchangeStep struct {
	command []byte
	wait    time.Duration
	done    bool
	result  []byte
	err     error
}

// newExchange runs sequence, which sends its commands with transceive,
// until it returns.
func newExchange(sequence func(transceive func(command []byte, wait time.Duration) ([]byte, error)) ([]byte, error)) *Exchange {
	e := &Exchange{steps: make(chan exchangeStep), responses: make(chan []byte), quit: make(chan struct{})}
	go func() {
		result, err := sequence(func(command []byte, wait time.Duration) ([]byte, error) {
			select {
			case e.steps <- exchangeStep{command: command, wait: wait}:
			case <-e.quit:
				return nil, errExchangeClosed
			}
			select {
			case resp := <-e.responses:
				return resp, nil
			case <-e.quit:
				return nil, errExchangeClosed
			}
		})
		select {
		case e.steps <- exchangeStep{done: true, result: result, err: err}:
		case <-e.quit:
		}
	}()
	e.current = <-e.steps
	return e
}

// Command is the next command APDU to send, or nil when the sequence is
// over.
func (e *Exchange) Command() []byte {
	if e.current.done {
		return nil
	}
	return e.current.command
}

// Wait is how long to wait before sending Command.
func (e *Exchange) Wait() time.Duration { return e.current.wait }

// Next passes the response to Command.
func (e *Exchange) Next(resp []byte) error {
	if e.current.done {
		return errors.New("nfcapdu: exchange already over")
	}
	select {
	case e.responses <- bytes.Clone(resp):
	case <-e.quit:
		return errExchangeClosed
	}
	select {
	case e.current = <-e.steps:
		return nil
	case <-e.quit:
		return errExchangeClosed
	}
}

// Result is the sequence's outcome, once Command is nil.
func (e *Exchange) Result() ([]byte, error) {
	if !e.current.done {
		return nil, errors.New("nfcapdu: exchange not over")
	}
	return e.current.result, e.current.err
}

// Close abandons the sequence.
func (e *Exchange) Close() { e.closeOnce.Do(func() { close(e.quit) }) }

// HandoverRead reads a Handover Select from the mdoc's emulated Type 4
// Tag: statically, or by TNEP negotiated handover when the tag offers
// it.
type HandoverRead struct {
	*Exchange
	negotiated bool
}

// Negotiated reports, once the read is over, that the tag offered TNEP
// and answered the Handover Request: the session transcript then binds
// both messages.
func (r *HandoverRead) Negotiated() bool { return r.negotiated }

// ReadHandover reads the Handover Select over a tag connection whose
// longest command or response APDU is maxTransceive bytes. hr is the
// Handover Request to send if the tag offers negotiated handover; with
// hr nil, such a tag is refused.
func ReadHandover(maxTransceive int, hr []byte) *HandoverRead {
	hr = bytes.Clone(hr) // the sequence outlives the call
	r := &HandoverRead{}
	r.Exchange = newExchange(func(transceive func([]byte, time.Duration) ([]byte, error)) ([]byte, error) {
		t := &type4Reader{transceive: transceive, maxTransceive: maxTransceive}
		hs, err := t.read(hr)
		r.negotiated = t.negotiated
		return hs, err
	})
	return r
}

// type4Reader reads, and for TNEP writes, an NFC Forum Type 4 Tag's NDEF
// file.
type type4Reader struct {
	transceive    func([]byte, time.Duration) ([]byte, error)
	maxTransceive int
	chunk         int // READ BINARY length
	writeChunk    int // UPDATE BINARY length
	maxSize       int // the NDEF file's, NLEN included
	writable      bool
	negotiated    bool
}

func (t *type4Reader) read(hr []byte) ([]byte, error) {
	t.chunk = min(255, t.maxTransceive-2)
	t.writeChunk = min(255, t.maxTransceive-5)
	if t.chunk < 15 {
		return nil, errors.New("nfcapdu: NFC transceive limit too small")
	}
	if _, err := t.command(concat([]byte{0, insSelect, 4, 0, lo(len(NDEFApplication))}, NDEFApplication, []byte{0}), 0); err != nil {
		return nil, err
	}
	if err := t.selectFile(fileCC); err != nil {
		return nil, err
	}
	ccLength, err := t.readLength()
	if err != nil {
		return nil, err
	}
	if ccLength < 15 || ccLength > 255 {
		return nil, errors.New("nfcapdu: invalid capability container length")
	}
	cc, err := t.readFile(ccLength)
	if err != nil {
		return nil, err
	}
	if cc[2]>>4 != 2 {
		return nil, errors.New("nfcapdu: unsupported Type 4 Tag mapping version")
	}
	mle := uint16At(cc, 3)
	if mle < 15 {
		return nil, errors.New("nfcapdu: invalid maximum READ BINARY length")
	}
	t.chunk = min(t.chunk, mle)
	t.writeChunk = min(t.writeChunk, uint16At(cc, 5))
	ndefFile, err := t.ndefFile(cc)
	if err != nil {
		return nil, err
	}
	if err := t.selectFile(ndefFile); err != nil {
		return nil, err
	}
	initial, err := t.readMessage()
	if err != nil {
		return nil, err
	}
	timing, found, err := tnepServiceParameters(initial)
	if err != nil || !found {
		return initial, err
	}
	t.negotiated = true
	if hr == nil || !t.writable {
		return nil, errors.New("nfcapdu: negotiated NFC handover unavailable")
	}
	status, err := t.transact(tnepSelect, timing)
	if err != nil {
		return nil, err
	}
	if p, err := tnepPayload(status, "Te"); err != nil || !bytes.Equal(p, []byte{0}) {
		return nil, errors.New("nfcapdu: TNEP service selection failed")
	}
	return t.transact(hr, timing)
}

// ndefFile finds the NDEF File Control TLV in a capability container,
// taking the file's maximum size and whether it is writable.
func (t *type4Reader) ndefFile(cc []byte) (int, error) {
	pos := 7
	for pos < len(cc) {
		typ := cc[pos]
		pos++
		if typ == 0 {
			continue
		}
		if typ == 0xfe {
			break
		}
		if pos >= len(cc) {
			return 0, errors.New("nfcapdu: truncated capability TLV")
		}
		length := int(cc[pos])
		pos++
		if pos+length > len(cc) {
			return 0, errors.New("nfcapdu: truncated capability TLV")
		}
		if typ == 4 && length == 6 && cc[pos+4] == 0 {
			t.maxSize = uint16At(cc, pos+2)
			t.writable = cc[pos+5] == 0
			if t.maxSize < 3 || t.maxSize > 32767 {
				break
			}
			return uint16At(cc, pos), nil
		}
		pos += length
	}
	return 0, errors.New("nfcapdu: no supported readable NDEF file")
}

func (t *type4Reader) readMessage() ([]byte, error) {
	nlen, err := t.readLength()
	if err != nil {
		return nil, err
	}
	if nlen == 0 || nlen > t.maxSize-2 {
		return nil, errors.New("nfcapdu: invalid NDEF length")
	}
	message := make([]byte, 0, nlen)
	for len(message) < nlen {
		part, err := t.readBinary(len(message)+2, min(t.chunk, nlen-len(message)), 0)
		if err != nil {
			return nil, err
		}
		message = append(message, part...)
	}
	return message, nil
}

func (t *type4Reader) writeMessage(message []byte) error {
	if !t.writable || t.writeChunk < 2 || len(message) < 1 || len(message) > t.maxSize-2 {
		return errors.New("nfcapdu: NDEF write exceeds the tag's capability")
	}
	if err := t.writeBinary(0, []byte{0, 0}); err != nil {
		return err
	}
	for written := 0; written < len(message); {
		end := min(written+t.writeChunk, len(message))
		if err := t.writeBinary(written+2, message[written:end]); err != nil {
			return err
		}
		written = end
	}
	return t.writeBinary(0, []byte{hi(len(message)), lo(len(message))})
}

// transact writes a TNEP message and polls for the tag's answer, at the
// service's minimum waiting time, for as many waiting time extensions
// as it allows.
func (t *type4Reader) transact(message []byte, timing tnepTiming) ([]byte, error) {
	if len(message) > timing.maxMessage {
		return nil, errors.New("nfcapdu: message exceeds the TNEP service's limit")
	}
	if err := t.writeMessage(message); err != nil {
		return nil, err
	}
	for range timing.waits + 1 {
		nlen, err := t.readBinary(0, 2, timing.wait())
		if err != nil {
			return nil, err
		}
		if uint16At(nlen, 0) > 0 {
			return t.readMessage()
		}
	}
	return nil, errors.New("nfcapdu: TNEP response timed out")
}

func (t *type4Reader) selectFile(file int) error {
	_, err := t.command([]byte{0, insSelect, 0, 0x0c, 2, hi(file), lo(file)}, 0)
	return err
}

func (t *type4Reader) readLength() (int, error) {
	b, err := t.readBinary(0, 2, 0)
	if err != nil {
		return 0, err
	}
	return uint16At(b, 0), nil
}

func (t *type4Reader) readFile(length int) ([]byte, error) {
	out := make([]byte, 0, length)
	for len(out) < length {
		part, err := t.readBinary(len(out), min(t.chunk, length-len(out)), 0)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	return out, nil
}

func (t *type4Reader) readBinary(offset, length int, wait time.Duration) ([]byte, error) {
	resp, err := t.command([]byte{0, insReadBinary, hi(offset), lo(offset), lo(length)}, wait)
	if err != nil {
		return nil, err
	}
	if len(resp) != length {
		return nil, errors.New("nfcapdu: short READ BINARY response")
	}
	return resp, nil
}

func (t *type4Reader) writeBinary(offset int, data []byte) error {
	_, err := t.command(concat([]byte{0, insUpdate, hi(offset), lo(offset), lo(len(data))}, data), 0)
	return err
}

// command sends one command APDU and returns its response data,
// refusing any status but success.
func (t *type4Reader) command(c []byte, wait time.Duration) ([]byte, error) {
	if len(c) > t.maxTransceive {
		return nil, errors.New("nfcapdu: NFC command exceeds the transceive limit")
	}
	resp, err := t.transceive(c, wait)
	if err != nil {
		return nil, err
	}
	data, sw, err := status(resp)
	if err != nil {
		return nil, err
	}
	if sw != swOK {
		return nil, fmt.Errorf("nfcapdu: NFC command failed with status %04X", sw)
	}
	return data, nil
}

func uint16At(b []byte, i int) int { return int(b[i])<<8 | int(b[i+1]) }

// SelectDataApplication is the command selecting the mdoc's NFC data
// application; its response must be success alone.
func SelectDataApplication() []byte {
	return concat([]byte{0, insSelect, 4, 0, lo(len(DataApplication))}, DataApplication, []byte{0})
}

// CheckDataApplicationSelected checks the response to
// SelectDataApplication.
func CheckDataApplicationSelected(resp []byte) error {
	if !bytes.Equal(resp, response(swOK, nil)) {
		return errors.New("nfcapdu: NFC data application unavailable")
	}
	return nil
}

// Transact sends one session message to the mdoc's NFC data application
// as a chain of ENVELOPE commands, and reads its answer through GET
// RESPONSE. Commands and responses fit both maxTransceive, the tag
// connection's limit, and the limits p the mdoc's Handover Select
// advertises, and stay short APDUs.
func Transact(maxTransceive int, p proximity.NFCDataParameters, message []byte) *Exchange {
	message = bytes.Clone(message) // the sequence outlives the call
	return newExchange(func(transceive func([]byte, time.Duration) ([]byte, error)) ([]byte, error) {
		return transact(transceive, maxTransceive, p, message)
	})
}

func transact(transceive func([]byte, time.Duration) ([]byte, error), maxTransceive int, p proximity.NFCDataParameters, message []byte) ([]byte, error) {
	commandLimit := min(255, maxTransceive-6, p.MaxCommand)
	responseLimit := min(256, maxTransceive-2, p.MaxResponse)
	if commandLimit < 1 || responseLimit < 1 {
		return nil, errors.New("nfcapdu: NFC controller limits unusable")
	}
	encoded, err := WrapDO53(message)
	if err != nil {
		return nil, err
	}
	resp, err := sendEnvelopes(transceive, encoded, commandLimit, responseLimit)
	if err != nil {
		return nil, err
	}
	return readResponses(transceive, resp, responseLimit)
}

// sendEnvelopes sends encoded as a chain of ENVELOPE commands of at most
// commandLimit bytes, returning the response to the last.
func sendEnvelopes(transceive func([]byte, time.Duration) ([]byte, error), encoded []byte, commandLimit, responseLimit int) ([]byte, error) {
	for offset := 0; ; {
		end := min(offset+commandLimit, len(encoded))
		if end == len(encoded) {
			return transceive(concat([]byte{0, insEnvelope, 0, 0, lo(end - offset)}, encoded[offset:end], []byte{lo(responseLimit)}), 0)
		}
		resp, err := transceive(concat([]byte{0x10, insEnvelope, 0, 0, lo(end - offset)}, encoded[offset:end]), 0)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(resp, response(swOK, nil)) {
			return nil, errors.New("nfcapdu: NFC command chain failed")
		}
		offset = end
	}
}

// readResponses assembles the answer from resp and the GET RESPONSE
// commands its 61XX status words call for.
func readResponses(transceive func([]byte, time.Duration) ([]byte, error), resp []byte, responseLimit int) ([]byte, error) {
	var assembled []byte
	for polls := 0; ; polls++ {
		if len(resp) < 2 || len(resp)-2 > responseLimit {
			return nil, errors.New("nfcapdu: invalid NFC response size")
		}
		if len(assembled)+len(resp)-2 > maxEncoded {
			return nil, errors.New("nfcapdu: NFC response too large")
		}
		data, sw, _ := status(resp)
		assembled = append(assembled, data...)
		if sw == swOK {
			return UnwrapDO53(assembled)
		}
		if len(resp) == 2 {
			return nil, errors.New("nfcapdu: empty NFC response continuation")
		}
		if sw&0xff00 != swMoreData || polls >= maxEncoded {
			return nil, errors.New("nfcapdu: NFC response chain failed")
		}
		le := responseLimit
		if indicated := sw & 0xff; indicated != 0 {
			le = min(indicated, responseLimit)
		}
		// GET RESPONSE is case 2: Le alone, no Lc.
		var err error
		if resp, err = transceive([]byte{0, insGetResponse, 0, 0, lo(le)}, 0); err != nil {
			return nil, err
		}
	}
}
