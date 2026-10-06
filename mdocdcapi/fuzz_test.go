package mdocdcapi

import (
	"context"
	"testing"
	"time"
)

// FuzzVerifyResponse feeds VerifyResponse arbitrary responses, seeded
// with a valid one: whatever a page posts back, it returns an error or
// a verified document, never panicking.
func FuzzVerifyResponse(f *testing.F) {
	h := newHarness(f, bothNames())
	f.Add(respond(f, h.request.Data, testOrigin, h.f))
	f.Add("")
	f.Add("gmVkY2FwaaA") // ["dcapi", {}]
	p := VerifyParams{Pending: h.request.Pending, IssuerKeys: fixedIssuerKey{pub: h.f.IssuerKey.Public()}}
	f.Fuzz(func(t *testing.T, response string) {
		p := p
		p.Response = response
		_, _ = VerifyResponse(context.Background(), p)
	})
}

// FuzzParseRequest feeds ParseRequest arbitrary request data, seeded
// with a signed request, and checks the reader and answers what parses:
// whatever a page asks, the wallet returns an error or a request, never
// panicking.
func FuzzParseRequest(f *testing.F) {
	h := newWalletHarness(f, bothNames())
	f.Add(h.data)
	f.Add([]byte(`{"deviceRequest":"oA","encryptionInfo":"oA"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := ParseRequest(data, testOrigin)
		if err != nil {
			return
		}
		_, _ = in.VerifyReader(h.roots, time.Time{})
		for i, d := range in.Documents {
			var elements [][2]string
			for ns, els := range d.Elements {
				for el := range els {
					elements = append(elements, [2]string{ns, el})
				}
			}
			_, _ = in.Respond(i, h.f.IssuerSigned, h.f.DeviceKey, elements)
		}
	})
}
