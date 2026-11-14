package walletflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/proximitytest"
	"github.com/idfoundry/oid4vcgo/internal/readerauth"
	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

func cborTag24(t *testing.T, b []byte) []byte {
	t.Helper()
	out, err := proximitytest.Tagged(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// proximityDoc is one DocRequest of a test request: a document type and
// one element of it, signed on its own by signer if not nil.
type proximityDoc struct {
	docType, ns, element string
	signer               *mdocReader
}

// deviceRequest is a DeviceRequest to send a holder: its documents,
// the readers signing it as a whole, in order, and its encoded
// deviceRequestInfo (#6.24(bstr)), or nil for none. replayed readers
// sign it as a whole too, after all, but over another session's
// transcript: a signature that doesn't verify in this one.
type deviceRequest struct {
	docs     []proximityDoc
	all      []mdocReader
	replayed []mdocReader
	info     []byte
}

// harmless and held are the two documents the trust tests ask for: one
// the holder has no credential for, and the held mdoc's family_name.
func harmless(signer *mdocReader) proximityDoc {
	return proximityDoc{"org.example.harmless", "x", "y", signer}
}

func held(signer *mdocReader) proximityDoc {
	return proximityDoc{walletflowtest.DocType, walletflowtest.NameSpace, "family_name", signer}
}

// establishment is r as the reader's SessionEstablishment for p. The
// signed structures are encoded here, not with internal/readerauth's
// builders.
func (r deviceRequest) establishment(t *testing.T, p *walletflow.ProximityPresentation) []byte {
	t.Helper()
	msg, err := proximitytest.SessionEstablishment(p.QRCode(), func(transcriptBytes []byte) ([]byte, error) {
		var tag cbor.Tag
		if err := cbor.Unmarshal(transcriptBytes, &tag); err != nil {
			return nil, err
		}
		transcript := cbor.RawMessage(tag.Content.([]byte))
		sign := func(reader mdocReader, authentication []any) (cbor.RawMessage, error) {
			inner, err := cbor.Marshal(authentication)
			if err != nil {
				return nil, err
			}
			return readerauth.Sign(reader.key.Signer, reader.key.Chain, cborTag24(t, inner))
		}
		var docRequests, items []any
		for _, d := range r.docs {
			encoded, err := cbor.Marshal(map[string]any{"docType": d.docType, "nameSpaces": map[string]map[string]bool{d.ns: {d.element: false}}})
			if err != nil {
				return nil, err
			}
			itemsBytes := cbor.RawMessage(cborTag24(t, encoded))
			doc := map[string]any{"itemsRequest": itemsBytes}
			if d.signer != nil {
				if doc["readerAuth"], err = sign(*d.signer, []any{"ReaderAuthentication", transcript, itemsBytes}); err != nil {
					return nil, err
				}
			}
			docRequests = append(docRequests, doc)
			items = append(items, itemsBytes)
		}
		req := map[string]any{"version": "1.1", "docRequests": docRequests}
		var info any
		if r.info != nil {
			req["deviceRequestInfo"] = cbor.RawMessage(r.info)
			info = cbor.RawMessage(r.info)
		}
		otherSession, err := cbor.Marshal([]any{nil, nil, "another session"})
		if err != nil {
			return nil, err
		}
		var all []any
		for _, signers := range []struct {
			readers    []mdocReader
			transcript cbor.RawMessage
		}{{r.all, transcript}, {r.replayed, otherSession}} {
			for _, reader := range signers.readers {
				sig, err := sign(reader, []any{"ReaderAuthenticationAll", signers.transcript, items, info})
				if err != nil {
					return nil, err
				}
				all = append(all, sig)
			}
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

// requestInfo is v encoded as a deviceRequestInfo.
func requestInfo(t *testing.T, v any) []byte {
	t.Helper()
	b, err := cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return cborTag24(t, b)
}

// purposeInfo is a deviceRequestInfo with one mandatory use case asking
// for both documents, with a purpose hint.
func purposeInfo(t *testing.T) []byte {
	return requestInfo(t, map[string]any{"useCases": []any{
		map[string]any{"mandatory": true, "documentSets": [][]int{{0, 1}}, "purposeHints": map[string]int{"org.example.controller": 3}},
	}})
}

// proximityWallet is the test mdoc's holder, trusting reader's CA, as
// two wallets: one requiring a trusted reader, one not.
type proximityWallet struct {
	reader  mdocReader
	wallets map[bool]*walletflow.Wallet
}

func newProximityWallet(t *testing.T) proximityWallet {
	t.Helper()
	f := newFixture(t, walletflowtest.Options{})
	reader := newMdocReader(t)
	pw := proximityWallet{reader: reader, wallets: map[bool]*walletflow.Wallet{}}
	for _, require := range []bool{false, true} {
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
			MdocReaderRoots: reader.roots, RequireTrustedMdocReader: require, Development: true,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		pw.wallets[require] = w
	}
	heldMdoc(t, receive(t, f, pw.wallets[false], walletflowtest.MdocConfigurationID))
	return pw
}

// start begins a presentation, with RequireTrustedMdocReader if
// require, and sends it r.
func (pw proximityWallet) start(t *testing.T, require bool, r deviceRequest) (*walletflow.ProximityPresentation, walletflow.ProximityEvent) {
	t.Helper()
	p, err := pw.wallets[require].StartProximityPresentation()
	if err != nil {
		t.Fatal(err)
	}
	return p, p.HandleMessage(context.Background(), r.establishment(t, p))
}

// A trusted reader's signature on one document request doesn't vouch
// for another the same request carries: the holder can answer either,
// so trust takes every request's readerAuth into account.
func TestProximityPresentation_TrustCoversEveryDocRequest(t *testing.T) {
	pw := newProximityWallet(t)
	r := pw.reader
	oneSigned := deviceRequest{docs: []proximityDoc{harmless(&r), held(nil)}}
	bothSigned := deviceRequest{docs: []proximityDoc{harmless(&r), held(&r)}}

	if _, ev := pw.start(t, true, oneSigned); ev.Request || !errors.Is(ev.Err, walletflow.ErrUntrustedVerifier) {
		t.Errorf("an unsigned document request beside a trusted one, RequireTrustedMdocReader: %+v, want refused as untrusted", ev)
	}
	if p, ev := pw.start(t, false, oneSigned); !ev.Request || p.Reader().Status != proximity.ReaderUnauthenticated {
		t.Errorf("an unsigned document request beside a trusted one: %+v, reader %v; want shown, unauthenticated", ev, p.Reader().Status)
	}
	if p, ev := pw.start(t, true, bothSigned); !ev.Request || p.Reader().Status != proximity.ReaderTrusted {
		t.Errorf("both signed by the trusted reader: %+v, reader %v; want trusted", ev, p.Reader().Status)
	}
}

// The reader's status and the information's coverage for every
// approved combination of whole-request and per-document signatures,
// with RequireTrustedMdocReader and without: a refused request
// publishes no request event and no information.
func TestProximityPresentation_WholeRequestTrust(t *testing.T) {
	pw := newProximityWallet(t)
	trusted, untrusted := pw.reader, newMdocReader(t)
	info := purposeInfo(t)
	both := func(signer *mdocReader) []proximityDoc { return []proximityDoc{harmless(signer), held(signer)} }
	for name, tc := range map[string]struct {
		req        deviceRequest
		want       proximity.ReaderStatus
		wantSigned bool
	}{
		"whole request by the trusted reader": {
			deviceRequest{docs: both(nil), all: []mdocReader{trusted}, info: info}, proximity.ReaderTrusted, true,
		},
		"untrusted, then trusted whole-request signer": {
			deviceRequest{docs: both(nil), all: []mdocReader{untrusted, trusted}, info: info}, proximity.ReaderTrusted, true,
		},
		"whole request by an untrusted reader": {
			deviceRequest{docs: both(nil), all: []mdocReader{untrusted}, info: info}, proximity.ReaderUntrusted, true,
		},
		"trusted documents, untrusted whole request": {
			deviceRequest{docs: both(&trusted), all: []mdocReader{untrusted}, info: info}, proximity.ReaderUntrusted, true,
		},
		"untrusted documents, trusted whole request": {
			deviceRequest{docs: both(&untrusted), all: []mdocReader{trusted}, info: info}, proximity.ReaderTrusted, true,
		},
		"documents only, trusted: information unsigned": {
			deviceRequest{docs: both(&trusted), info: info}, proximity.ReaderTrusted, false,
		},
		"an invalid extra whole-request signature": {
			deviceRequest{docs: both(nil), all: []mdocReader{trusted}, replayed: []mdocReader{trusted}, info: info}, proximity.ReaderInvalid, false,
		},
		"unsigned": {
			deviceRequest{docs: both(nil), info: info}, proximity.ReaderUnauthenticated, false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, ev := pw.start(t, false, tc.req)
			if !ev.Request || p.Reader().Status != tc.want {
				t.Fatalf("enforcement off: %+v, reader %v (%v); want a request, %v", ev, p.Reader().Status, p.Reader().Err, tc.want)
			}
			got := p.RequestInfo()
			if got == nil || got.Signed != tc.wantSigned || len(got.UseCases) != 1 || got.UseCases[0].PurposeHints["org.example.controller"] != 3 {
				t.Errorf("RequestInfo = %+v, want the use case, signed %v", got, tc.wantSigned)
			}

			p, ev = pw.start(t, true, tc.req)
			if tc.want != proximity.ReaderTrusted {
				if ev.Request || !ev.Ended || !errors.Is(ev.Err, walletflow.ErrUntrustedVerifier) || p.RequestInfo() != nil || len(p.Requests()) != 0 {
					t.Errorf("enforcement on: %+v, info %+v; want refused, nothing published", ev, p.RequestInfo())
				}
			} else if !ev.Request || p.RequestInfo() == nil {
				t.Errorf("enforcement on: %+v; want the trusted request shown", ev)
			}
		})
	}
}
