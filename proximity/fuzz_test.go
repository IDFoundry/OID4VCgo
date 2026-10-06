package proximity

import (
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

func FuzzNewReaderSession(f *testing.F) {
	f.Add("mdoc:" + base64.RawURLEncoding.EncodeToString(mustHex(f, annexDDeviceEngagement)))
	holder, err := NewDeviceSession(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(holder.QRCode())
	f.Add("mdoc:")
	f.Fuzz(func(t *testing.T, qr string) {
		r, err := NewReaderSession(qr)
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
		_, _ = s.reader.Verify(msg, fx.roots, time.Now())
	})
}
