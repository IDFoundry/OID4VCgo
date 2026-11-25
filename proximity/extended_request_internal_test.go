package proximity

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"
)

// A reader that finds ExtendedRequestSupport in the holder's QR
// engagement sends a second-edition request, signed as a whole, with
// use cases and purpose hints: the holder reads them, signed, and
// recognizes the reader, both sides having derived one
// SessionTranscript from the engagement as sent; the reader verifies
// the reply. A reader that ignores the capability still sends a
// first-edition request, which the holder answers as before.
func TestExtendedRequestSupport_EndToEnd(t *testing.T) {
	fx := issueFixture(t, mDL)
	signer := newTestSigner(t)
	elements := map[string][]string{mDLNS: {"age_over_18"}}
	info := infoOf(t, map[string]any{"useCases": []any{
		map[string]any{"mandatory": true, "documentSets": [][]int{{0}}, "purposeHints": map[string]int{"org.example.purpose": 3, "org.example.negative": -2}},
		map[string]any{"mandatory": false, "documentSets": [][]int{}},
	}})
	wantUseCases := []UseCase{
		{Mandatory: true, DocumentSets: [][]int{{0}}, PurposeHints: map[string]int32{"org.example.purpose": 3, "org.example.negative": -2}},
		{Mandatory: false, DocumentSets: [][]int{}, PurposeHints: map[string]int32{}},
	}

	for name, extended := range map[string]bool{"reads the capability": true, "ignores the capability": false} {
		t.Run(name, func(t *testing.T) {
			holder, err := NewDeviceSession(nil)
			if err != nil {
				t.Fatal(err)
			}
			reader, err := NewReaderSession(holder.QRCode(), devReader()...)
			if err != nil {
				t.Fatal(err)
			}
			if !reader.engagement.extendedRequestSupport {
				t.Fatal("the reader didn't find ExtendedRequestSupport in the engagement")
			}

			var est []byte
			if extended {
				req := testRequest{docs: []testDoc{{docType: mDL}}, all: []testSigner{signer}, info: info}.build(t, reader.SessionTranscriptBytes())
				if est, err = reader.establishment(req); err != nil {
					t.Fatal(err)
				}
				reader.requests = []readerRequest{{docType: mDL, requested: newRequestedSet(elements)}}
			} else if est, err = reader.Establishment(mDL, elements); err != nil {
				t.Fatal(err)
			}

			reqBytes, err := holder.HandleSessionEstablishment(est)
			if err != nil {
				t.Fatalf("HandleSessionEstablishment: %v", err)
			}
			if !bytes.Equal(holder.SessionTranscriptBytes(), reader.SessionTranscriptBytes()) {
				t.Fatal("the holder's and reader's SessionTranscriptBytes differ")
			}
			req, err := DecodeDeviceRequest(reqBytes)
			if err != nil {
				t.Fatalf("DecodeDeviceRequest: %v", err)
			}
			auth := holder.VerifyDeviceRequest(req, ReaderTrust{Roots: signer.roots})
			got := req.RequestInfo()
			if !extended {
				if got != nil || auth.RequestInfoSigned {
					t.Errorf("a first-edition request has information %+v, signed %v", got, auth.RequestInfoSigned)
				}
			} else {
				if got == nil {
					t.Fatalf("RequestInfo is nil (%v)", req.RequestInfoError())
				}
				if !reflect.DeepEqual(got.UseCases, wantUseCases) {
					t.Errorf("use cases %+v, want %+v", got.UseCases, wantUseCases)
				}
				if auth.Reader.Status != ReaderTrusted || !auth.RequestInfoSigned {
					t.Errorf("reader %v (%v), information signed %v; want trusted, signed", auth.Reader.Status, auth.Reader.Err, auth.RequestInfoSigned)
				}
			}

			docs := req.DocRequests()
			if len(docs) != 1 || docs[0].DocType != mDL {
				t.Fatalf("DocRequests = %+v", docs)
			}
			f := flow{holder: holder, reader: reader, req: docs[0]}
			v, err := reader.Verify(context.Background(), f.respond(t, fx, docs[0].Elements), fx.roots, time.Now())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if v.Claims[mDLNS]["age_over_18"] != true {
				t.Errorf("Claims = %v", v.Claims)
			}
		})
	}
}
