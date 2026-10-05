package proximity

import (
	"encoding/base64"
	"errors"
	"testing"
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
