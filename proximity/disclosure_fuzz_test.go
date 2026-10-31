package proximity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
)

// FuzzDeviceRequestDisclosure takes a DeviceRequest's plaintext, which
// a reader controls once a session is established, through what the
// holder does with it: ParseDeviceRequest, VerifyReaderAuth, and
// BuildDeviceResponse with the consented elements (a subset of each
// request's, by mask, and maybe one it didn't request). A DeviceResponse
// it builds is for the requested document type and discloses only
// elements both requested and consented to; one with an unrequested
// element is never built. The session is established once, with one
// reader key, so the fuzzer spends its time past the encryption.
func FuzzDeviceRequestDisclosure(f *testing.F) {
	fx := issueFixture(f, mDL)
	seed, err := encodeDeviceRequest(mDL, map[string][]string{mDLNS: {"age_over_18", "family_name"}}, nil)
	if err != nil {
		f.Fatal(err)
	}
	readerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	holder, err := NewDeviceSession(nil)
	if err != nil {
		f.Fatal(err)
	}
	reader, err := newReaderSession(readerKey, holder.DeviceEngagementBytes(), nullHandover)
	if err != nil {
		f.Fatal(err)
	}
	msg, err := reader.establishment(seed)
	if err != nil {
		f.Fatal(err)
	}
	if _, err := holder.HandleSessionEstablishment(msg); err != nil {
		f.Fatal(err)
	}
	transcript := holder.SessionTranscriptBytes()
	f.Add(seed, uint64(1<<64-1), false, "", "")
	f.Add(seed, uint64(1), true, mDLNS, "document_number")
	f.Add(mustHex(f, annexDDeviceRequest), uint64(0b101), false, "", "")
	other, err := encodeDeviceRequest("org.example.other", map[string][]string{mDLNS: {"given_name"}}, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(other, uint64(1), false, "", "")
	f.Fuzz(func(t *testing.T, plaintext []byte, consent uint64, addUnrequested bool, ns, element string) {
		reqs, err := ParseDeviceRequest(plaintext)
		if err != nil {
			return
		}
		for _, req := range reqs {
			if got := holder.VerifyReaderAuth(req, ReaderTrust{}); got.Status == ReaderTrusted {
				t.Fatalf("readerAuth trusted with no roots: %+v", got)
			}
			var elements [][2]string
			for i, e := range req.Elements {
				if i >= 64 || consent&(1<<i) != 0 {
					elements = append(elements, e)
				}
			}
			extra := [2]string{ns, element}
			unrequested := addUnrequested && !slices.Contains(req.Elements, extra)
			if addUnrequested {
				elements = append(elements, extra)
			}
			resp, err := BuildDeviceResponse(req, fx.issuerSigned, fx.deviceKey, transcript, elements)
			if err != nil {
				continue
			}
			if unrequested {
				t.Fatalf("built a DeviceResponse disclosing %v, which %v didn't request", extra, req.Elements)
			}
			doc, err := oid4vpmdoc.UnmarshalDeviceResponse(resp)
			if err != nil {
				t.Fatalf("BuildDeviceResponse wrote a DeviceResponse that doesn't decode: %v", err)
			}
			if doc.DocType != req.DocType {
				t.Fatalf("a DeviceResponse for %q answered a request for %q", doc.DocType, req.DocType)
			}
			for gotNS, items := range doc.IssuerSigned.NameSpaces {
				for _, item := range items {
					e := [2]string{gotNS, item.ElementIdentifier}
					if !slices.Contains(req.Elements, e) || !slices.Contains(elements, e) {
						t.Fatalf("disclosed %v: requested %v, consented %v", e, req.Elements, elements)
					}
				}
			}
		}
	})
}
