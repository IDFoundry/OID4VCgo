//go:build mobiletest

package mobile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/proximitytest"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// wholeRequest is the reader's SessionEstablishment for p asking for
// the held mdoc's family_name: signed per document by docSigner and as
// a whole by allSigners, each if set, with info (#6.24(bstr)) as its
// deviceRequestInfo when not nil. The signed structures are encoded
// here, not with internal/readerauth's builders.
func wholeRequest(t *testing.T, p *ProximityPresentation, docSigner *testReader, allSigners []testReader, info []byte) []byte {
	t.Helper()
	qr := decode[struct {
		QRCode string `json:"qr_code"`
	}](t, p.Engagement()).QRCode
	tag24 := func(b []byte) cbor.RawMessage {
		out, err := proximitytest.Tagged(b)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	msg, err := proximitytest.SessionEstablishment(qr, func(transcriptBytes []byte) ([]byte, error) {
		var tag cbor.Tag
		if err := cbor.Unmarshal(transcriptBytes, &tag); err != nil {
			return nil, err
		}
		transcript := cbor.RawMessage(tag.Content.([]byte))
		sign := func(r testReader, authentication []any) (cbor.RawMessage, error) {
			inner, err := cbor.Marshal(authentication)
			if err != nil {
				return nil, err
			}
			return readerauth.Sign(r.key.Signer, r.key.Chain, tag24(inner))
		}
		items, err := cbor.Marshal(map[string]any{"docType": walletflowtest.DocType, "nameSpaces": map[string]map[string]bool{walletflowtest.NameSpace: {"family_name": true}}})
		if err != nil {
			return nil, err
		}
		itemsBytes := tag24(items)
		doc := map[string]any{"itemsRequest": itemsBytes}
		if docSigner != nil {
			if doc["readerAuth"], err = sign(*docSigner, []any{"ReaderAuthentication", transcript, itemsBytes}); err != nil {
				return nil, err
			}
		}
		req := map[string]any{"version": "1.1", "docRequests": []any{doc}}
		var infoItem any
		if info != nil {
			req["deviceRequestInfo"] = cbor.RawMessage(info)
			infoItem = cbor.RawMessage(info)
		}
		var all []any
		for _, r := range allSigners {
			sig, err := sign(r, []any{"ReaderAuthenticationAll", transcript, []any{itemsBytes}, infoItem})
			if err != nil {
				return nil, err
			}
			all = append(all, sig)
		}
		if len(all) > 0 {
			req["readerAuthAll"] = all
		}
		return cbor.Marshal(req)
	})
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func infoBytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := proximitytest.Tagged(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// requestJSON is Request's members, request_info as its raw JSON.
type requestJSON struct {
	Reader struct {
		Status string `json:"status"`
	} `json:"reader"`
	RequestInfo json.RawMessage `json:"request_info"`
}

// Request's request_info through whole-message handling: an exact null
// before a request, for a first-edition request and for one without
// information; present empty information keeps its array; use cases,
// with int32-boundary purpose codes, arrive whole; signed is coverage,
// not trust, and never comes from per-document trust.
func TestSessions_ProximityRequestInfo(t *testing.T) {
	trusted, other := newTestReader(t), newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, trusted)
	h.receive(t)
	hinted := infoBytes(t, map[string]any{"useCases": []any{
		map[string]any{"mandatory": true, "documentSets": [][]int{{0}, {0, 0}}, "purposeHints": map[string]int64{"org.example.max": 2147483647, "org.example.min": -2147483648}},
		map[string]any{"mandatory": false, "documentSets": [][]int{}},
	}})

	before, err := h.w.StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(decode[requestJSON](t, before.Request()).RequestInfo); got != "null" {
		t.Errorf("before the request: request_info %s, want null", got)
	}
	if !strings.Contains(before.Request(), `"request_info":null`) {
		t.Errorf("request_info isn't an explicit null: %s", before.Request())
	}

	for name, tc := range map[string]struct {
		doc        *testReader
		all        []testReader
		info       []byte
		wantStatus string
		wantInfo   string
	}{
		"first edition, signed per document": {&trusted, nil, nil, "trusted", `null`},
		"whole request, no information":      {nil, []testReader{trusted}, nil, "trusted", `null`},
		"whole request, empty information": {nil, []testReader{trusted}, infoBytes(t, map[string]any{}), "trusted",
			`{"use_cases":[],"signed":true}`},
		"whole request, use cases": {nil, []testReader{trusted}, hinted, "trusted",
			`{"use_cases":[{"mandatory":true,"document_sets":[[0],[0,0]],"purpose_hints":{"org.example.max":2147483647,"org.example.min":-2147483648}},{"mandatory":false,"document_sets":[],"purpose_hints":{}}],"signed":true}`},
		"untrusted whole request: signed, untrusted": {&trusted, []testReader{other}, hinted, "untrusted",
			`{"use_cases":[{"mandatory":true,"document_sets":[[0],[0,0]],"purpose_hints":{"org.example.max":2147483647,"org.example.min":-2147483648}},{"mandatory":false,"document_sets":[],"purpose_hints":{}}],"signed":true}`},
		"document trust alone: unsigned": {&trusted, nil, infoBytes(t, map[string]any{}), "trusted",
			`{"use_cases":[],"signed":false}`},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := h.w.StartProximityPresentation()
			if err != nil {
				t.Fatal(err)
			}
			ev := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), wholeRequest(t, p, tc.doc, tc.all, tc.info)))
			if ev.Event != "request" {
				t.Fatalf("HandleMessage = %+v", ev)
			}
			got := decode[requestJSON](t, p.Request())
			if got.Reader.Status != tc.wantStatus || string(got.RequestInfo) != tc.wantInfo {
				t.Errorf("reader %s, request_info %s; want %s, %s", got.Reader.Status, got.RequestInfo, tc.wantStatus, tc.wantInfo)
			}
		})
	}
}

// A refused request — an untrusted whole-request signer under
// require_trusted_mdoc_reader, or malformed information — leaves
// request_info null.
func TestSessions_ProximityRequestInfoRefused(t *testing.T) {
	trusted, other := newTestReader(t), newTestReader(t)
	h := newHarness(t, false).withReaderRoots(t, trusted)
	h.receive(t)
	strict := h.withConfig(t, map[string]any{"mdoc_reader_roots": trusted.caPEM, "require_trusted_mdoc_reader": true})
	for name, tc := range map[string]struct {
		h    harness
		all  []testReader
		info []byte
		code string
	}{
		"untrusted whole-request signer": {strict, []testReader{other}, infoBytes(t, map[string]any{}), CodeUntrustedVerifier},
		"malformed information":          {h, []testReader{trusted}, infoBytes(t, map[string]any{"useCases": nil}), CodeProtocol},
	} {
		t.Run(name, func(t *testing.T) {
			p, err := tc.h.w.StartProximityPresentation()
			if err != nil {
				t.Fatal(err)
			}
			ev := decode[proximityEvent](t, p.HandleMessage(NewOperation(0), wholeRequest(t, p, &trusted, tc.all, tc.info)))
			if ev.Event != "ended" || !strings.HasPrefix(ev.Error, "["+tc.code+"]") {
				t.Errorf("HandleMessage = %+v, want ended with %s", ev, tc.code)
			}
			if got := string(decode[requestJSON](t, p.Request()).RequestInfo); got != "null" {
				t.Errorf("request_info %s, want null", got)
			}
		})
	}
}
