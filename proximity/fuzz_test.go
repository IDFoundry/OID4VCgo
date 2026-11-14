package proximity

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

// The fuzz targets below check that attacker-supplied bytes never panic
// and that every rejection of a message's own bytes closes the session.

func FuzzParseDeviceRequest(f *testing.F) {
	f.Add(mustHex(f, annexDDeviceRequest))
	f.Add([]byte{0xa0})
	f.Fuzz(func(t *testing.T, b []byte) {
		reqs, err := ParseDeviceRequest(b)
		if err == nil && len(reqs) == 0 {
			t.Fatal("no error and no DocRequests")
		}
		for _, r := range reqs {
			if r.DocType == "" || len(r.Elements) == 0 || r.ItemsRequestBytes == nil {
				t.Fatalf("accepted an incomplete DocRequest: %+v", r)
			}
		}
	})
}

// FuzzVerifyReaderAuth: a received readerAuth never panics, and with
// no trust anchors is never trusted; ParseDeviceRequest's errors are
// always decoding or validation errors.
func FuzzVerifyReaderAuth(f *testing.F) {
	reqs, err := ParseDeviceRequest(mustHex(f, annexDDeviceRequest))
	if err != nil {
		f.Fatal(err)
	}
	transcript := mustHex(f, annexDSessionTranscriptBytes)
	f.Add(reqs[0].ReaderAuth, reqs[0].ItemsRequestBytes)
	f.Add([]byte{0x84, 0x40, 0xa0, 0xf6, 0x40}, reqs[0].ItemsRequestBytes)
	f.Fuzz(func(t *testing.T, readerAuth, items []byte) {
		req := DocRequest{ReaderAuth: readerAuth, ItemsRequestBytes: items}
		if got := VerifyReaderAuth(req, transcript, ReaderTrust{}); got.Status == ReaderTrusted || got.Err == nil {
			t.Fatalf("trusted with no roots: %+v", got)
		}
		if _, err := ParseDeviceRequest(items); err != nil && !errors.Is(err, ErrCBORDecoding) && !errors.Is(err, ErrCBORValidation) {
			t.Fatalf("ParseDeviceRequest error is neither decoding nor validation: %v", err)
		}
	})
}

func FuzzNewReaderSession(f *testing.F) {
	f.Add("mdoc:" + base64.RawURLEncoding.EncodeToString(mustHex(f, annexDDeviceEngagement)))
	holder, err := NewDeviceSession(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(holder.QRCode())
	f.Add("mdoc:")
	f.Fuzz(func(t *testing.T, qr string) {
		r, err := NewReaderSession(qr, devReader()...)
		if err == nil && len(r.ServiceUUID()) != 36 {
			t.Fatalf("accepted an engagement without a 16-byte UUID: %q", r.ServiceUUID())
		}
	})
}

func FuzzHandleSessionEstablishment(f *testing.F) {
	f.Add(mustHex(f, annexDSessionEstablishment))
	f.Add(mustHex(f, annexDSessionData))
	f.Fuzz(func(t *testing.T, msg []byte) {
		s := annexDDeviceSession(t)
		if _, err := s.HandleSessionEstablishment(msg); err != nil {
			if _, _, err := s.HandleSessionData(msg); !errors.Is(err, ErrSessionClosed) {
				t.Fatalf("session usable after a failed establishment: %v", err)
			}
		}
	})
}

func FuzzHandleSessionData(f *testing.F) {
	f.Add(mustHex(f, annexDSessionTermination))
	f.Add(mustHex(f, annexDSessionData))
	f.Add([]byte{0xa1, 0x64, 'd', 'a', 't', 'a', 0x40})
	establishment := mustHex(f, annexDSessionEstablishment)
	f.Fuzz(func(t *testing.T, msg []byte) {
		s := annexDDeviceSession(t)
		if _, err := s.HandleSessionEstablishment(establishment); err != nil {
			t.Fatal(err)
		}
		_, status, err := s.HandleSessionData(msg)
		if err != nil || status != nil {
			if _, err := s.Encrypt([]byte{0xa0}, false); !errors.Is(err, ErrSessionClosed) {
				t.Fatalf("session usable after an error or status: %v", err)
			}
		}
	})
}

// FuzzReaderVerify feeds ReaderSession.Verify arbitrary plaintext,
// encrypted as an established session's holder would — past session
// encryption, into what a malicious mdoc controls: the DeviceResponse.
// Whatever it sends, Verify returns an error or a verified document,
// never panicking.
func FuzzReaderVerify(f *testing.F) {
	fx := issueFixture(f, mDL)
	seed := establish(f, mDL, map[string][]string{mDLNS: {"age_over_18"}})
	resp, err := buildDeviceResponse(fx.issuerSigned, mDL, fx.deviceKey, seed.holder.SessionTranscriptBytes(), [][2]string{{mDLNS, "age_over_18"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(resp)
	f.Add([]byte{0xa0})
	f.Add([]byte{0xa1, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x63, 0x31, 0x2e, 0x30})
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		s := establish(t, mDL, map[string][]string{mDLNS: {"age_over_18"}})
		msg, err := s.holder.Encrypt(plaintext, false)
		if err != nil {
			return
		}
		_, _ = s.reader.Verify(context.Background(), msg, fx.roots, time.Now())
	})
}

// FuzzDecodeDeviceRequest: the request-level decoder never panics,
// fails only with decoding or validation errors, and accepts only
// requests within its limits whose document references name their
// documents. Its seeds are second-edition requests with information,
// signed and not, and Annex D's.
func FuzzDecodeDeviceRequest(f *testing.F) {
	f.Add(mustHex(f, annexDDeviceRequest))
	f.Add([]byte{0xa0})
	for _, seed := range fuzzRequestSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := DecodeDeviceRequest(b)
		if err != nil {
			if req != nil {
				t.Fatal("an error and a request")
			}
			if !errors.Is(err, ErrCBORDecoding) && !errors.Is(err, ErrCBORValidation) {
				t.Fatalf("error is neither decoding nor validation: %v", err)
			}
			return
		}
		docs := req.DocRequests()
		if len(docs) == 0 || len(docs) > MaxDocRequests || len(req.readerAuthAll) > MaxReaderSignatures {
			t.Fatalf("accepted %d documents and %d signatures", len(docs), len(req.readerAuthAll))
		}
		info := req.RequestInfo()
		if info == nil {
			return
		}
		if info.Signed || len(info.UseCases) > MaxUseCases {
			t.Fatalf("accepted information %+v", info)
		}
		sets, refs, hints := 0, 0, 0
		for _, uc := range info.UseCases {
			if uc.DocumentSets == nil || uc.PurposeHints == nil {
				t.Fatal("a nil collection")
			}
			sets += len(uc.DocumentSets)
			hints += len(uc.PurposeHints)
			for _, set := range uc.DocumentSets {
				refs += len(set)
				for _, i := range set {
					if i < 0 || i >= len(docs) {
						t.Fatalf("document reference %d of %d", i, len(docs))
					}
				}
			}
			for id := range uc.PurposeHints {
				if len(id) > MaxControllerIDBytes {
					t.Fatalf("a %d-byte controller ID", len(id))
				}
			}
		}
		if sets > MaxDocumentSets || refs > MaxDocumentReferences || hints > MaxPurposeHints {
			t.Fatalf("over a total: %d sets, %d references, %d hints", sets, refs, hints)
		}
	})
}

// FuzzVerifyDeviceRequest: verifying any decodable request never
// panics, and with no trust anchors never trusts a reader; coverage
// needs information and a whole-request signature.
func FuzzVerifyDeviceRequest(f *testing.F) {
	for _, seed := range fuzzRequestSeeds(f) {
		f.Add(seed)
	}
	f.Add(mustHex(f, annexDDeviceRequest))
	transcript := fuzzTranscript(f)
	annexD := mustHex(f, annexDSessionTranscriptBytes)
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := DecodeDeviceRequest(b)
		if err != nil {
			return
		}
		for _, session := range [][]byte{transcript, annexD} {
			got := VerifyDeviceRequest(req, session, ReaderTrust{})
			if got.Reader.Status == ReaderTrusted || got.Reader.Err == nil {
				t.Fatalf("trusted with no roots: %+v", got)
			}
			if got.RequestInfoSigned && (req.info == nil || len(req.readerAuthAll) == 0 || got.Reader.Status == ReaderInvalid) {
				t.Fatalf("coverage without information, a whole-request signature or validity: %+v", got)
			}
		}
	})
}

// fuzzTranscript is the transcript fuzzRequestSeeds are signed over.
func fuzzTranscript(tb testing.TB) []byte {
	tb.Helper()
	transcript, err := encMode.Marshal([]any{nil, nil, []any{"fuzz", []byte{1}}})
	if err != nil {
		tb.Fatal(err)
	}
	b, err := wrapTag24(transcript)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// fuzzRequestSeeds are second-edition requests, signed over
// fuzzTranscript.
func fuzzRequestSeeds(f *testing.F) [][]byte {
	f.Helper()
	a := newTestSigner(f)
	transcript := fuzzTranscript(f)
	return [][]byte{
		testRequest{docs: testDocs(2, &a), all: []testSigner{a}, info: sampleInfo(f)}.build(f, transcript),
		testRequest{docs: testDocs(1, nil), all: []testSigner{a, a}, info: infoOf(f, map[string]any{})}.build(f, transcript),
		testRequest{docs: testDocs(3, nil), info: sampleInfo(f)}.build(f, transcript),
	}
}
