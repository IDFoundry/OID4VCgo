package mdocdcapi

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// unreachableTransport fails every request with err.
type unreachableTransport struct{ err error }

func (u unreachableTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, u.err }

// VerifyResponseDocuments checks every document's status, not just the
// first's: a response whose second document's status list can't be
// fetched is refused, and Accept never runs. A revoked document can't
// pass by coming with another that's valid.
func TestVerifyResponseDocuments_ChecksEachDocumentsStatus(t *testing.T) {
	h := newMultiHarness(t)
	h.fixtures[2] = testmdoc.IssueWith(t, func(c *mdoc.Claims) {
		c.DocType = multiTypes[2]
		c.Status = &mdoc.StatusListRef{Idx: 7, URI: "https://issuer.example.com/statuslists/1"}
	})
	h.keys[multiTypes[2]] = h.fixtures[2].IssuerKey.Public()
	encrypted, err := h.incoming.RespondDocuments(context.Background(), []Answer{h.answer(0), h.answer(2)})
	if err != nil {
		t.Fatal(err)
	}
	unreachable := errors.New("unreachable")
	accepted := false
	_, err = VerifyResponseDocuments(context.Background(), VerifyParams{
		Pending: h.request.Pending, Response: base64.RawURLEncoding.EncodeToString(encrypted), IssuerKeys: h.keys,
		Assurance: verifier.AssuranceDevelopment,
		Status: &verifier.StatusPolicy{Checker: statuslist.Checker{
			Fetcher: statuslist.Fetcher{HTTP: &http.Client{Transport: unreachableTransport{unreachable}}, UncheckedTransport: true}, Roots: x509.NewCertPool(),
		}, StatusIssuers: verifier.AnyStatusListSigner},
		Accept: func(context.Context, string, verifier.VerifyResponseResult) error {
			accepted = true
			return nil
		},
	})
	if !errors.Is(err, unreachable) || accepted {
		t.Errorf("VerifyResponseDocuments = %v, Accept ran %v; want refused by the second document's status", err, accepted)
	}
}
