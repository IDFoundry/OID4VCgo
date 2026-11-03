package nfcapdu

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/proximity"
)

// drive runs e against tag, as the native reader does, returning its
// result and the commands it sent.
func drive(t *testing.T, e *Exchange, tag func([]byte) []byte) ([]byte, [][]byte, error) {
	t.Helper()
	defer e.Close()
	var sent [][]byte
	for c := e.Command(); c != nil; c = e.Command() {
		sent = append(sent, c)
		if err := e.Next(tag(c)); err != nil {
			t.Fatalf("Next: %v", err)
		}
	}
	result, err := e.Result()
	return result, sent, err
}

// holderTag answers commands with h, as the native holder does, and
// fails the test if a response is held back for a session message.
func holderTag(t *testing.T, h *Holder) func([]byte) []byte {
	return func(c []byte) []byte {
		step := h.Process(c)
		if step.Response == nil {
			t.Fatalf("command %X awaited a session message", c)
		}
		return step.Response
	}
}

func ok(t *testing.T, resp []byte) []byte {
	t.Helper()
	data, sw, err := status(resp)
	if err != nil || sw != swOK {
		t.Fatalf("response %X, want success", resp)
	}
	return data
}

// fixture is an NDEF message of one record with a size-byte payload.
func fixture(size int) []byte {
	return concat([]byte{0xc1, 2, 0, 0, byte(size >> 8), byte(size), 'H', 's'}, bytes.Repeat([]byte{7}, size))
}

var (
	selectNDEF     = concat([]byte{0, insSelect, 4, 0, 7}, NDEFApplication)
	selectNDEFFile = []byte{0, insSelect, 0, 0x0c, 2, 0xe1, 4}
)

func writeAt(offset int, data []byte) []byte {
	return concat([]byte{0, insUpdate, byte(offset >> 8), byte(offset), byte(len(data))}, data)
}

func TestParseCommand(t *testing.T) {
	for _, tc := range []struct {
		apdu []byte
		data []byte
		le   int
	}{
		{[]byte{0, insGetResponse, 0, 0}, nil, 0},
		{[]byte{0, insGetResponse, 0, 0, 0}, nil, 256},
		{[]byte{0, insGetResponse, 0, 0, 0, 0, 0}, nil, 65536},
		{[]byte{0, insEnvelope, 0, 0, 2, 4, 5}, []byte{4, 5}, 0},
		{[]byte{0, insEnvelope, 0, 0, 2, 4, 5, 9}, []byte{4, 5}, 9},
		{[]byte{0, insEnvelope, 0, 0, 0, 0, 2, 4, 5, 0, 0}, []byte{4, 5}, 65536},
	} {
		c, parsed := ParseCommand(tc.apdu)
		if !parsed || !bytes.Equal(c.Data, tc.data) || c.Le != tc.le {
			t.Errorf("ParseCommand(%X) = %+v, %v; want data %X, Le %d", tc.apdu, c, parsed, tc.data, tc.le)
		}
	}
	for _, bad := range [][]byte{
		{0, insEnvelope, 0},
		{0, insEnvelope, 0, 0, 4, 1},       // data shorter than Lc
		{0, insEnvelope, 0, 0, 0, 1},       // extended header cut short
		{0, insEnvelope, 0, 0, 1, 4, 5, 6}, // two trailing bytes for a short Le
		{0, insEnvelope, 0, 0, 0, 0, 0, 4}, // extended Lc 0
	} {
		if _, parsed := ParseCommand(bad); parsed {
			t.Errorf("ParseCommand(%X) parsed a malformed APDU", bad)
		}
	}
}

func TestClassify(t *testing.T) {
	data := concat([]byte{0, insSelect, 4, 0, 7}, DataApplication)
	for _, tc := range []struct {
		apdu []byte
		want CommandKind
	}{
		{selectNDEF, CommandSelectNDEF},
		{data, CommandSelectData},
		// ISO/IEC 18013-5 Table 8's own form: P2 0x0C, no Le.
		{concat([]byte{0, insSelect, 4, 0x0c, 7}, DataApplication), CommandSelectData},
		{concat([]byte{0, insSelect, 4, 0x04, 7}, DataApplication), CommandOther},
		{concat([]byte{0, insSelect, 4, 0, 1}, []byte{1}), CommandSelectOther},
		{concat([]byte{1, insSelect, 4, 0, 7}, NDEFApplication), CommandOther},
		{[]byte{0, insReadBinary, 0, 0, 2}, CommandOther},
		{[]byte{1}, CommandOther},
	} {
		if got := Classify(tc.apdu); got != tc.want {
			t.Errorf("Classify(%X) = %d, want %d", tc.apdu, got, tc.want)
		}
	}
}

func TestStaticReadsAreStableAndCompleteOnce(t *testing.T) {
	message := fixture(600)
	original := bytes.Clone(message)
	h, err := NewHolder(HolderOptions{HandoverSelect: message})
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	tag := func(c []byte) []byte {
		step := h.Process(c)
		if step.HandoverRead {
			reads++
		}
		return step.Response
	}
	for range 2 {
		hs, _, err := drive(t, ReadHandover(261, nil).Exchange, tag)
		if err != nil || !bytes.Equal(hs, message) {
			t.Fatalf("ReadHandover = %X, %v", hs, err)
		}
		h.Deactivate(true, false)
	}
	if reads != 1 {
		t.Errorf("HandoverRead %d times, want once", reads)
	}
	clear(message) // NewHolder copied the caller's buffer.
	if hs, _, _ := drive(t, ReadHandover(261, nil).Exchange, tag); !bytes.Equal(hs, original) {
		t.Errorf("after the caller's buffer changed: %X", hs)
	}
}

func TestPartialReadDoesNotCompleteHandover(t *testing.T) {
	h, err := NewHolder(HolderOptions{HandoverSelect: make([]byte, 300)})
	if err != nil {
		t.Fatal(err)
	}
	h.Process(selectNDEF)
	h.Process(selectNDEFFile)
	for range 10 {
		if h.Process([]byte{0, insReadBinary, 0, 2, 50}).HandoverRead {
			t.Fatal("a partial read completed the handover")
		}
	}
	h.Deactivate(false, false)
	if resp := h.Process([]byte{0, insReadBinary, 0, 0, 2}).Response; !bytes.Equal(resp, response(swConditionsNotMet, nil)) {
		t.Errorf("READ BINARY after field loss = %X, want 6985", resp)
	}
}

func TestMalformedCommandsAlwaysGetAStatus(t *testing.T) {
	h, err := NewHolder(HolderOptions{HandoverSelect: []byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewPCG(917, 0))
	for range 20000 {
		b := make([]byte, random.IntN(600))
		for i := range b {
			b[i] = byte(random.Uint32())
		}
		if resp := h.Process(b).Response; len(resp) < 2 {
			t.Fatalf("Process(%X) = %X", b, resp)
		}
	}
}

func TestReaderRefusesShortAndFailedResponses(t *testing.T) {
	for _, resp := range [][]byte{{}, response(swFileNotFound, nil), response(swOK, nil)} {
		if _, _, err := drive(t, ReadHandover(261, nil).Exchange, func([]byte) []byte { return resp }); err == nil {
			t.Errorf("a tag answering %X was read", resp)
		}
	}
	if _, _, err := drive(t, ReadHandover(16, nil).Exchange, func([]byte) []byte { return nil }); err == nil {
		t.Error("a 16-byte transceive limit was accepted")
	}
}

func TestNegotiatedHandoverInFragments(t *testing.T) {
	request := fixture(550)
	answer := bytes.Repeat([]byte{2}, 400)
	negotiations := 0
	h, err := NewHolder(HolderOptions{Negotiate: func(hr []byte) ([]byte, error) {
		if !bytes.Equal(hr, request) {
			t.Errorf("Negotiate got %X", hr)
		}
		negotiations++
		return answer, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	tag := func(c []byte) []byte {
		step := h.Process(c)
		if step.HandoverRead {
			reads++
		}
		return step.Response
	}
	r := ReadHandover(128, request)
	hs, _, err := drive(t, r.Exchange, tag)
	if err != nil || !bytes.Equal(hs, answer) {
		t.Fatalf("ReadHandover = %X, %v", hs, err)
	}
	if !r.Negotiated() || negotiations != 1 || reads != 1 {
		t.Errorf("Negotiated %v, %d negotiations, %d handover reads", r.Negotiated(), negotiations, reads)
	}
	for _, tc := range []struct{ in, want []byte }{
		{tnepSuccess, tnepSuccess},
		{shortRecord("Ts", []byte{0}), tnepParameters},
	} {
		if got, err := h.tnep.transact(tc.in); err != nil || !bytes.Equal(got, tc.want) {
			t.Errorf("transact(%X) = %X, %v; want %X", tc.in, got, err, tc.want)
		}
	}
	if _, err := h.tnep.transact(request); err == nil {
		t.Error("a deselected service answered a Handover Request")
	}
}

func TestStaticOnlyReaderOnNegotiatedHolder(t *testing.T) {
	h, err := NewHolder(HolderOptions{Negotiate: func([]byte) ([]byte, error) {
		t.Error("a static read negotiated")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	read := false
	_, _, err = drive(t, ReadHandover(128, nil).Exchange, func(c []byte) []byte {
		step := h.Process(c)
		read = read || step.HandoverRead
		return step.Response
	})
	if err == nil || read {
		t.Errorf("a reader without a Handover Request: %v, HandoverRead %v", err, read)
	}
	if d := h.Deactivate(false, false); d.Cancel {
		t.Error("field loss before any Handover Request cancelled the presentation")
	}
}

func TestIncompleteNDEFWritesNeverCommit(t *testing.T) {
	commits := 0
	h, err := NewHolder(HolderOptions{Negotiate: func(hr []byte) ([]byte, error) { commits++; return hr, nil }})
	if err != nil {
		t.Fatal(err)
	}
	h.Process(selectNDEF)
	h.Process(selectNDEFFile)
	ok(t, h.Process(writeAt(0, []byte{0, 0})).Response)
	h.Process(writeAt(2, []byte{1, 2}))
	if resp := h.Process(writeAt(0, []byte{0, 3})).Response; !bytes.Equal(resp, response(swConditionsNotMet, nil)) {
		t.Errorf("committing a partly written message = %X, want 6985", resp)
	}
	h.Deactivate(false, false)
	if resp := h.Process(writeAt(0, []byte{0, 2})).Response; !bytes.Equal(resp, response(swConditionsNotMet, nil)) {
		t.Errorf("committing after field loss = %X, want 6985", resp)
	}
	if commits != 0 {
		t.Errorf("%d commits", commits)
	}
}

func TestTNEPFindsTheHandoverServiceAmongOthers(t *testing.T) {
	other := shortRecord("Tp", []byte{0x10, 1, 'x', 0, 16, 15, 1, 0})
	other[0] = 0x91 // message begin, short record
	handover := bytes.Clone(tnepParameters)
	handover[0] = 0x51 // message end, short record
	timing, found, err := tnepServiceParameters(concat(other, handover))
	if err != nil || !found || timing != (tnepTiming{wt: 16, waits: 15, maxMessage: maxNDEF}) {
		t.Fatalf("tnepServiceParameters = %+v, %v, %v", timing, found, err)
	}
	if got := timing.wait(); got != 8*time.Millisecond {
		t.Errorf("WT 16 waits %v, want 8ms", got)
	}
	// A Service Select in a normal (four-byte length) record.
	normal := concat([]byte{0xc1, 2, 0, 0, 0, byte(len(tnepSelectPayload)), 'T', 's'}, tnepSelectPayload)
	holder := &tnepHolder{negotiate: func([]byte) ([]byte, error) { return fixture(1), nil }}
	if got, err := holder.transact(normal); err != nil || !bytes.Equal(got, tnepSuccess) {
		t.Errorf("transact(normal Ts) = %X, %v", got, err)
	}
	if _, _, err := tnepServiceParameters(concat(handover[:1], tnepParameters[1:], handover)); err == nil {
		t.Error("two handover services were accepted")
	}
}

func TestFrozenNegotiatedHandoverCancelsOnFieldLoss(t *testing.T) {
	answered := false
	h, err := NewHolder(HolderOptions{Negotiate: func([]byte) ([]byte, error) { answered = true; return fixture(120), nil }})
	if err != nil {
		t.Fatal(err)
	}
	errFieldLost := errors.New("field lost")
	e := ReadHandover(128, fixture(1)).Exchange
	defer e.Close()
	for c := e.Command(); c != nil; c = e.Command() {
		if c[1] == insReadBinary && answered {
			break // the field drops before the reader reads Hs
		}
		if err := e.Next(h.Process(c).Response); err != nil {
			t.Fatal(err)
		}
	}
	if !answered {
		t.Fatal(errFieldLost)
	}
	if d := h.Deactivate(false, false); !d.Cancel {
		t.Error("field loss after Hs was created but before it was read didn't cancel")
	}
}

func TestUncommittedAttemptCanBeRetried(t *testing.T) {
	hs := fixture(120)
	for _, negotiated := range []bool{false, true} {
		opts := HolderOptions{HandoverSelect: hs}
		var hr []byte
		if negotiated {
			opts = HolderOptions{Negotiate: func([]byte) ([]byte, error) { return hs, nil }}
			hr = fixture(1)
		}
		h, err := NewHolder(opts)
		if err != nil {
			t.Fatal(err)
		}
		h.Process(selectNDEF)
		h.Process(selectNDEFFile)
		h.Process([]byte{0, insReadBinary, 0, 2, 1})
		if d := h.Deactivate(false, false); d.Cancel {
			t.Errorf("negotiated %v: an uncommitted attempt cancelled", negotiated)
		}
		read := false
		got, _, err := drive(t, ReadHandover(128, hr).Exchange, func(c []byte) []byte {
			step := h.Process(c)
			read = read || step.HandoverRead
			return step.Response
		})
		if err != nil || !bytes.Equal(got, hs) || !read {
			t.Errorf("negotiated %v: retry = %X, %v, HandoverRead %v", negotiated, got, err, read)
		}
	}
}

func TestQRWinLeavesTheTagIntact(t *testing.T) {
	h, err := NewHolder(HolderOptions{Negotiate: func([]byte) ([]byte, error) { return fixture(10), nil }})
	if err != nil {
		t.Fatal(err)
	}
	h.Process(selectNDEF)
	if d := h.Deactivate(false, true); d.Cancel || d.DataClosed {
		t.Errorf("field loss after QR won: %+v", d)
	}
}

func TestDO53(t *testing.T) {
	for _, size := range []int{0, 1, 127, 128, 255, 256, 65535, 65536, 180000} {
		original := bytes.Repeat([]byte{3}, size)
		encoded, err := WrapDO53(original)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := UnwrapDO53(encoded); err != nil || !bytes.Equal(got, original) {
			t.Errorf("size %d: round trip failed: %v", size, err)
		}
	}
	for _, bad := range [][]byte{{}, {0x53, 0x80}, {0x53, 0x81, 1, 7}, {0x53, 5, 1}, {0x54, 0}, {0x53, 0x84, 0, 0, 0, 1, 0}} {
		if _, err := UnwrapDO53(bad); err == nil {
			t.Errorf("UnwrapDO53(%X) accepted", bad)
		}
	}
	if _, err := WrapDO53(make([]byte, MaxMessage+1)); err == nil {
		t.Error("a message over MaxMessage was wrapped")
	}
}

// dataHolder serves NFC data retrieval behind a static Handover Select.
func newDataHolder(t *testing.T) (*Holder, []byte) {
	t.Helper()
	s, err := proximity.NewNFCDataDeviceSession(nil, proximity.NFCDataParameters{MaxCommand: 255, MaxResponse: 256})
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHolder(HolderOptions{HandoverSelect: s.HandoverSelect(), Data: true})
	if err != nil {
		t.Fatal(err)
	}
	return h, s.HandoverSelect()
}

func TestLargeResponseChainsAndWaitsForConsent(t *testing.T) {
	h, hs := newDataHolder(t)
	p, err := proximity.ParseNFCDataHandover(hs)
	if err != nil {
		t.Fatal(err)
	}
	request := bytes.Repeat([]byte{3}, 1500)
	portrait := bytes.Repeat([]byte{5}, 180000)
	if !h.Process(SelectDataApplication()).DataSelected {
		t.Fatal("selecting the data application wasn't reported")
	}
	delivered := false
	got, sent, err := drive(t, Transact(128, p, request), func(c []byte) []byte {
		step := h.Process(c)
		delivered = delivered || step.Delivered
		if step.Message == nil {
			return step.Response
		}
		// The final ENVELOPE waits while the holder shows consent.
		if !bytes.Equal(step.Message, request) {
			t.Errorf("Message = %d bytes", len(step.Message))
		}
		first, err := h.Respond(portrait)
		if err != nil {
			t.Fatal(err)
		}
		return first.Response
	})
	if err != nil || !bytes.Equal(got, portrait) || !delivered {
		t.Fatalf("Transact = %d bytes, %v, delivered %v", len(got), err, delivered)
	}
	chained, getResponses := false, 0
	for _, c := range sent {
		chained = chained || c[0] == 0x10
		if c[1] == insGetResponse {
			getResponses++
			if len(c) != 5 {
				t.Errorf("GET RESPONSE %X carries more than Le", c)
			}
		}
	}
	if !chained || getResponses < 100 {
		t.Errorf("chained %v, %d GET RESPONSEs", chained, getResponses)
	}
	if _, err := h.Respond(portrait); err == nil {
		t.Error("Respond without a pending message succeeded")
	}
}

// TestSelectDataApplication selects the NFC data application with ISO/IEC
// 18013-5 §11.2 Table 8's command (P2 0x0C, no Le), and with P2 0 and an
// Le as some readers send it: both get 9000 alone (Table 9). Our reader
// sends Table 8's, and takes a success carrying data too.
func TestSelectDataApplication(t *testing.T) {
	table8 := concat([]byte{0, insSelect, 4, 0x0c, 7}, DataApplication)
	if !bytes.Equal(SelectDataApplication(), table8) {
		t.Errorf("SelectDataApplication = %X, want %X", SelectDataApplication(), table8)
	}
	for _, c := range [][]byte{table8, concat([]byte{0, insSelect, 4, 0, 7}, DataApplication, []byte{0})} {
		h, _ := newDataHolder(t)
		if step := h.Process(c); !bytes.Equal(step.Response, response(swOK, nil)) || !step.DataSelected {
			t.Errorf("SELECT %X = %X, selected %v", c, step.Response, step.DataSelected)
		}
	}
	h, _ := newDataHolder(t)
	if step := h.Process(concat([]byte{0, insSelect, 4, 0x04, 7}, DataApplication)); step.DataSelected {
		t.Error("SELECT with P2 04 selected the data application")
	}
	if err := CheckDataApplicationSelected(response(swOK, []byte{0x6f, 0})); err != nil {
		t.Errorf("success with an FCI: %v", err)
	}
	for _, resp := range [][]byte{response(swFileNotFound, nil), {0x90}} {
		if CheckDataApplicationSelected(resp) == nil {
			t.Errorf("CheckDataApplicationSelected(%X) succeeded", resp)
		}
	}
}

func TestFieldLossEndsDataRetrieval(t *testing.T) {
	h, _ := newDataHolder(t)
	h.Process(SelectDataApplication())
	h.Process([]byte{0x10, insEnvelope, 0, 0, 2, 0x53, 10})
	if d := h.Deactivate(true, false); !d.DataClosed {
		t.Error("field loss during data retrieval didn't end it")
	}
	if resp := h.Process([]byte{0, insGetResponse, 0, 0, 0}).Response; !bytes.Equal(resp, response(swConditionsNotMet, nil)) {
		t.Errorf("GET RESPONSE after field loss = %X, want 6985", resp)
	}
	fresh, _ := newDataHolder(t)
	if err := CheckDataApplicationSelected(fresh.Process(SelectDataApplication()).Response); err != nil {
		t.Error(err)
	}
}

func TestRefuseMessage(t *testing.T) {
	h, _ := newDataHolder(t)
	h.Process(SelectDataApplication())
	wrapped, _ := WrapDO53([]byte{1})
	step := h.Process(concat([]byte{0, insEnvelope, 0, 0, byte(len(wrapped))}, wrapped, []byte{0}))
	if step.Message == nil {
		t.Fatal("no message")
	}
	if resp := h.RefuseMessage(); !bytes.Equal(resp, response(swConditionsNotMet, nil)) {
		t.Errorf("RefuseMessage = %X", resp)
	}
	if _, err := h.Respond([]byte{2}); err == nil {
		t.Error("a refused message was answered")
	}
}

func TestExchangeClose(t *testing.T) {
	e := ReadHandover(261, nil).Exchange
	e.Close()
	if err := e.Next(response(swOK, nil)); err == nil {
		t.Error("Next after Close succeeded")
	}
	e.Close()
}

// TestRefusals checks the status word each refused command gets.
func TestRefusals(t *testing.T) {
	envelope := func(cla byte, data []byte, le ...byte) []byte {
		return concat([]byte{cla, insEnvelope, 0, 0, byte(len(data))}, data, le)
	}
	type check struct {
		apdu []byte
		want int
	}
	tag := []check{
		{[]byte{1}, swWrongLength},
		{[]byte{0x80, insReadBinary, 0, 0, 2}, swCLANotSupported},
		{[]byte{0, insReadBinary, 0, 0, 2}, swConditionsNotMet}, // nothing selected
		{concat([]byte{0, insSelect, 4, 1, 7}, NDEFApplication), swWrongP1P2},
		{concat([]byte{0, insSelect, 4, 0, 1}, []byte{9}), swFileNotFound},
		{selectNDEF, swOK},
		{[]byte{0, insReadBinary, 0, 0, 2}, swConditionsNotMet}, // no file selected
		{[]byte{0, insSelect, 0, 0, 2, 0xe1, 4}, swWrongP1P2},
		{[]byte{0, insSelect, 0, 0x0c, 2, 0xe1, 5}, swFileNotFound},
		{[]byte{0, insSelect, 0, 0x0c, 2, 0xe1, 3}, swOK},
		{[]byte{0, insReadBinary, 0x80, 0, 2}, swWrongP1P2},
		{[]byte{0, insReadBinary, 0, 0}, swWrongP1P2},
		{[]byte{0, insReadBinary, 0, 15, 2}, swWrongOffset},
		{[]byte{0, insReadBinary, 0, 0, 0}, swWrongLe},
		{[]byte{0, insReadBinary, 0, 0, 0, 1, 0}, swWrongLe},
		{[]byte{0, insReadBinary, 0, 10, 10}, swEndOfFile},
		{writeAt(2, []byte{1}), swCommandNotAllowedEF},
		{[]byte{0, 0x2a, 0, 0}, swINSNotSupported},
	}
	h, err := NewHolder(HolderOptions{HandoverSelect: fixture(20)})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range tag {
		if _, sw, _ := status(h.Process(c.apdu).Response); sw != c.want {
			t.Errorf("tag: %X = %04X, want %04X", c.apdu, sw, c.want)
		}
	}
	data := []check{
		{[]byte{0, insGetResponse, 0, 0, 0}, swConditionsNotMet}, // data not selected: the tag answers
		{concat([]byte{0, insSelect, 4, 0, 7}, DataApplication, []byte{0}), swOK},
		{concat([]byte{0, insSelect, 4, 1, 7}, DataApplication), swFileNotFound},
		{[]byte{1}, swWrongLength},
		{[]byte{0, insEnvelope, 1, 0, 1, 0}, swWrongP1P2},
		{[]byte{0, 0x2a, 0, 0}, swINSNotSupported},
		{envelope(0x80, []byte{1}, 0), swCLANotSupported},
		{envelope(0x10, []byte{1}, 0), swWrongP1P2},
		{envelope(0, []byte{1}), swWrongP1P2},
		{envelope(0, []byte{0x53, 0x81, 1}, 0), swWrongData}, // truncated DO53
		{envelope(0, []byte{0x54, 0}, 0), swWrongData},
		{[]byte{0, insGetResponse, 0, 0, 0}, swConditionsNotMet},
		{[]byte{0, insGetResponse, 0, 0, 1, 0, 0}, swWrongP1P2},
	}
	h, _ = newDataHolder(t)
	for _, c := range data {
		if _, sw, _ := status(h.Process(c.apdu).Response); sw != c.want {
			t.Errorf("data: %X = %04X, want %04X", c.apdu, sw, c.want)
		}
	}
	h.Close()
	if _, sw, _ := status(h.Process(SelectDataApplication()).Response); sw != swConditionsNotMet {
		t.Errorf("SELECT after Close = %04X, want 6985", sw)
	}
	if _, err := (&Holder{}).Respond(nil); err == nil {
		t.Error("Respond without data retrieval succeeded")
	}
}

// TestExchangesCopyTheirInputs: a caller (gomobile's, for one) may reuse
// hr or message once ReadHandover or Transact returns.
func TestExchangesCopyTheirInputs(t *testing.T) {
	request, answer := fixture(40), fixture(30)
	h, err := NewHolder(HolderOptions{Negotiate: func(hr []byte) ([]byte, error) {
		if !bytes.Equal(hr, fixture(40)) {
			t.Errorf("Negotiate got %X", hr)
		}
		return answer, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := ReadHandover(128, request)
	clear(request)
	if _, _, err := drive(t, r.Exchange, holderTag(t, h)); err != nil {
		t.Fatal(err)
	}

	d, hs := newDataHolder(t)
	p, _ := proximity.ParseNFCDataHandover(hs)
	d.Process(SelectDataApplication())
	message := []byte("request")
	x := Transact(261, p, message)
	clear(message)
	got, _, err := drive(t, x, func(c []byte) []byte {
		step := d.Process(c)
		if step.Message == nil {
			return step.Response
		}
		if string(step.Message) != "request" {
			t.Errorf("Message = %q", step.Message)
		}
		first, _ := d.Respond(step.Message)
		return first.Response
	})
	if err != nil || string(got) != "request" {
		t.Errorf("Transact = %q, %v", got, err)
	}
}
