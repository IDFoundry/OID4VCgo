package mdocresponse_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/mdocresponse"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// document is a fixture's mdoc as a Document of docType, its device
// signature over a placeholder transcript: neither function verifies
// one.
func document(t *testing.T, docType string) oid4vpmdoc.Document {
	t.Helper()
	f := testmdoc.Issue(t)
	// #6.24(bstr .cbor []).
	transcript := []byte{0xd8, 0x18, 0x41, 0x80}
	deviceSigned, err := mdoc.SignDeviceSignature(f.DeviceKey, cose.ES256, transcript, docType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatal(err)
	}
	return oid4vpmdoc.Document{DocType: docType, IssuerSigned: f.IssuerSigned, DeviceSigned: deviceSigned}
}

// With one document, the encoding is oid4vpmdoc's exactly, so a holder
// answering one document sends the bytes it always has.
func TestMarshalOneIsOID4VPMdocs(t *testing.T) {
	doc := document(t, testmdoc.DocType)
	got, err := mdocresponse.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := oid4vpmdoc.MarshalDeviceResponse(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Marshal = %x\nwant      %x", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	docs := []oid4vpmdoc.Document{document(t, "org.example.a"), document(t, "org.example.b")}
	b, err := mdocresponse.Marshal(docs...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := mdocresponse.Unmarshal(b, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].DocType != "org.example.a" || got[1].DocType != "org.example.b" {
		t.Fatalf("Unmarshal = %d documents %+v", len(got), got)
	}
}

func TestRefuses(t *testing.T) {
	if _, err := mdocresponse.Marshal(); err == nil {
		t.Error("Marshal of no documents succeeded")
	}
	if _, err := mdocresponse.Marshal(oid4vpmdoc.Document{}); err == nil {
		t.Error("Marshal of a document without a docType succeeded")
	}
	two, err := mdocresponse.Marshal(document(t, "org.example.a"), document(t, "org.example.a"))
	if err != nil {
		t.Fatal(err)
	}
	three, err := mdocresponse.Marshal(document(t, "org.example.a"), document(t, "org.example.b"), document(t, "org.example.c"))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		data            []byte
		maxBytes, maxDo int
		want            string
	}{
		"two of a type":  {two, 1 << 20, 2, "two"},
		"too many":       {three, 1 << 20, 2, "over 2"},
		"too large":      {three, 16, 3, "bytes"},
		"not a response": {[]byte{0xa0}, 1 << 20, 3, "version"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mdocresponse.Unmarshal(tc.data, tc.maxBytes, tc.maxDo); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Unmarshal = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

// Decode leaves the status and an empty response to its caller, as an
// in-person reader reports them, and marks decoding faults ErrDecoding.
func TestDecode(t *testing.T) {
	// {"version": "1.0", "documentErrors": [{"org.example.a": 10}], "status": 0}
	onlyErrors := []byte{0xa3, 0x67, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x63, '1', '.', '0',
		0x6e, 'd', 'o', 'c', 'u', 'm', 'e', 'n', 't', 'E', 'r', 'r', 'o', 'r', 's',
		0x81, 0xa1, 0x6d, 'o', 'r', 'g', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'a', 0x0a,
		0x66, 's', 't', 'a', 't', 'u', 's', 0x00}
	resp, err := mdocresponse.Decode(onlyErrors, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Documents) != 0 || len(resp.DocumentErrors) != 1 || resp.DocumentErrors[0]["org.example.a"] != 10 || resp.Status != 0 {
		t.Fatalf("Decode = %+v", resp)
	}
	if _, err := mdocresponse.Unmarshal(onlyErrors, 1<<20, 2); err == nil || !strings.Contains(err.Error(), "no documents") {
		t.Errorf("Unmarshal of documentErrors alone = %v", err)
	}
	// {"version": "1.0", "status": 20}
	declined := []byte{0xa2, 0x67, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0x63, '1', '.', '0', 0x66, 's', 't', 'a', 't', 'u', 's', 0x14}
	if resp, err := mdocresponse.Decode(declined, 1<<20, 2); err != nil || resp.Status != 20 {
		t.Errorf("Decode of status 20 = %+v, %v", resp, err)
	}
	for name, data := range map[string][]byte{"not CBOR": {0xa2, 0x67}, "too large": onlyErrors} {
		maxBytes := 1 << 20
		if name == "too large" {
			maxBytes = 8
		}
		if _, err := mdocresponse.Decode(data, maxBytes, 2); !errors.Is(err, mdocresponse.ErrDecoding) {
			t.Errorf("%s: Decode = %v, want ErrDecoding", name, err)
		}
	}
}
