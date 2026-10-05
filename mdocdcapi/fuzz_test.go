package mdocdcapi

import (
	"context"
	"testing"
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
