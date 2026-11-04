package proximity

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// The document types of a request for several documents: an mDL, a
// photo ID and a payment credential, each issued under its own IACA.
var multiTypes = []string{mDL, "org.iso.23220.photoid.1", "org.example.payment.1"}

// multiFlow is an established session whose reader asked for docTypes,
// given_name and family_name each, and the requests as the holder
// decoded them.
type multiFlow struct {
	holder *DeviceSession
	reader *ReaderSession
	reqs   []DocRequest
}

func establishDocuments(t *testing.T, docTypes []string) multiFlow {
	t.Helper()
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewReaderSession(holder.QRCode(), devReader()...)
	if err != nil {
		t.Fatal(err)
	}
	var docs []DocumentRequest
	for _, dt := range docTypes {
		docs = append(docs, DocumentRequest{DocType: dt, Elements: map[string][]string{mDLNS: {"given_name", "family_name"}}})
	}
	est, err := reader.EstablishmentDocuments(docs)
	if err != nil {
		t.Fatal(err)
	}
	reqBytes, err := holder.HandleSessionEstablishment(est)
	if err != nil {
		t.Fatal(err)
	}
	reqs, err := ParseDeviceRequest(reqBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != len(docTypes) {
		t.Fatalf("holder saw %d DocRequests, want %d", len(reqs), len(docTypes))
	}
	for i, r := range reqs {
		if r.DocType != docTypes[i] {
			t.Fatalf("DocRequest %d is for %q, want %q", i, r.DocType, docTypes[i])
		}
	}
	return multiFlow{holder: holder, reader: reader, reqs: reqs}
}

func multiFixtures(t *testing.T) (map[string]fixture, *x509.CertPool) {
	t.Helper()
	fixtures := map[string]fixture{}
	roots := x509.NewCertPool()
	for _, dt := range multiTypes {
		fx := issueFixture(t, dt)
		fixtures[dt] = fx
		roots.AddCert(fx.ca)
	}
	return fixtures, roots
}

// A reader asking for three documents gets back any of them in one
// DeviceResponse, each verified against the request for its type,
// disclosing only what the holder chose; the first by DeviceMac when
// the holder's key agrees keys, the others signed.
func TestRespondDocuments(t *testing.T) {
	fixtures, roots := multiFixtures(t)
	for _, answered := range [][]int{{0, 1, 2}, {0, 2}, {1}} {
		t.Run(fmt.Sprint(answered), func(t *testing.T) {
			f := establishDocuments(t, multiTypes)
			var docs []oid4vpmdoc.Document
			for n, i := range answered {
				fx := fixtures[multiTypes[i]]
				var doc oid4vpmdoc.Document
				var err error
				if n == 0 {
					doc, err = BuildDocumentMAC(f.reqs[i], fx.issuerSigned, agreeOnlyKey{fx.deviceKey}, f.holder.EReaderKey(), f.holder.SessionTranscriptBytes(), [][2]string{{mDLNS, "given_name"}})
				} else {
					doc, err = BuildDocument(f.reqs[i], fx.issuerSigned, fx.deviceKey, f.holder.SessionTranscriptBytes(), [][2]string{{mDLNS, "given_name"}})
				}
				if err != nil {
					t.Fatal(err)
				}
				docs = append(docs, doc)
			}
			resp, err := MarshalDeviceResponse(docs...)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := f.holder.Encrypt(resp, true)
			if err != nil {
				t.Fatal(err)
			}
			vs, err := f.reader.VerifyDocuments(context.Background(), msg, roots, time.Now())
			if err != nil {
				t.Fatalf("VerifyDocuments: %v", err)
			}
			if len(vs) != len(answered) {
				t.Fatalf("%d documents verified, want %d", len(vs), len(answered))
			}
			for n, i := range answered {
				v := vs[n]
				if v.DocType != multiTypes[i] {
					t.Errorf("document %d is %q, want %q", n, v.DocType, multiTypes[i])
				}
				if got := v.Claims[mDLNS]; len(v.Claims) != 1 || len(got) != 1 || got["given_name"] != "Alice" {
					t.Errorf("%s disclosed %v, want only given_name", v.DocType, v.Claims)
				}
				want := mdoc.DeviceAuthSignature
				if n == 0 {
					want = mdoc.DeviceAuthMAC
				}
				if v.DeviceAuth != want {
					t.Errorf("%s authenticated by %v, want %v", v.DocType, v.DeviceAuth, want)
				}
			}
		})
	}
}

// A reader asks for each document type once, at most MaxDocRequests,
// and at least one.
func TestEstablishmentDocumentsRefuses(t *testing.T) {
	holder, err := NewDeviceSession(nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := func(dt string) DocumentRequest {
		return DocumentRequest{DocType: dt, Elements: map[string][]string{mDLNS: {"given_name"}}}
	}
	many := make([]DocumentRequest, MaxDocRequests+1)
	for i := range many {
		many[i] = doc(fmt.Sprintf("org.example.%d", i))
	}
	for name, docs := range map[string][]DocumentRequest{
		"none":       nil,
		"twice":      {doc(mDL), doc(mDL)},
		"too many":   many,
		"no element": {doc(mDL), {DocType: "org.example.empty"}},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := NewReaderSession(holder.QRCode(), devReader()...)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.EstablishmentDocuments(docs); err == nil {
				t.Fatal("EstablishmentDocuments succeeded")
			}
			// Nothing was sent: the reader can still ask.
			if _, err := r.Establishment(mDL, map[string][]string{mDLNS: {"given_name"}}); err != nil {
				t.Fatalf("Establishment after a refusal: %v", err)
			}
		})
	}
}

// A reader that asked for several documents verifies with
// VerifyDocuments, and refuses a document it didn't ask for, two of one
// type, or more documents than it asked for.
func TestVerifyDocumentsRefuses(t *testing.T) {
	fixtures, roots := multiFixtures(t)
	given := [][2]string{{mDLNS, "given_name"}}
	unchecked := func(f multiFlow, dt string) oid4vpmdoc.Document {
		t.Helper()
		fx := fixtures[dt]
		doc, err := buildDocument(fx.issuerSigned, dt, fx.deviceKey, f.holder.SessionTranscriptBytes(), given)
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	send := func(t *testing.T, f multiFlow, docs ...oid4vpmdoc.Document) []byte {
		t.Helper()
		resp, err := MarshalDeviceResponse(docs...)
		if err != nil {
			t.Fatal(err)
		}
		msg, err := f.holder.Encrypt(resp, true)
		if err != nil {
			t.Fatal(err)
		}
		return msg
	}

	t.Run("Verify", func(t *testing.T) {
		f := establishDocuments(t, multiTypes[:2])
		msg := send(t, f, unchecked(f, multiTypes[0]))
		if _, err := f.reader.Verify(context.Background(), msg, roots, time.Now()); err == nil || !strings.Contains(err.Error(), "VerifyDocuments") {
			t.Fatalf("Verify after two documents were requested: %v", err)
		}
	})
	for name, tc := range map[string]struct {
		docs func(f multiFlow) []oid4vpmdoc.Document
		want string
	}{
		"unrequested type": {func(f multiFlow) []oid4vpmdoc.Document {
			return []oid4vpmdoc.Document{unchecked(f, multiTypes[0]), unchecked(f, multiTypes[2])}
		}, "wasn't requested"},
		"two of one type": {func(f multiFlow) []oid4vpmdoc.Document {
			return []oid4vpmdoc.Document{unchecked(f, multiTypes[0]), unchecked(f, multiTypes[0])}
		}, "two"},
		"more than requested": {func(f multiFlow) []oid4vpmdoc.Document {
			return []oid4vpmdoc.Document{unchecked(f, multiTypes[0]), unchecked(f, multiTypes[1]), unchecked(f, multiTypes[2])}
		}, "3 documents for 2"},
	} {
		t.Run(name, func(t *testing.T) {
			f := establishDocuments(t, multiTypes[:2])
			_, err := f.reader.VerifyDocuments(context.Background(), send(t, f, tc.docs(f)...), roots, time.Now())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("VerifyDocuments = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}
