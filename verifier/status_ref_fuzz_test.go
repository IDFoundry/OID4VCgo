package verifier_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// refusingTransport fails every request, so a status check that gets as
// far as fetching a list fails without touching the network.
type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("fuzz: no network")
}

// FuzzStatusReference reads arbitrary status references: an SD-JWT VC's
// "status" claim (any JSON value) and an mdoc MSO's status (any mix of
// status_list and identifier_list). Besides never panicking, a status
// that is present is never read as no status: StatusListRef reports a
// reference or an error, never neither; RequireStatusReference accepts
// the credential only for a reference it can check; and a StatusPolicy
// whose lists can't be fetched never passes it. A credential with no
// status reads as none, which RequireStatusReference refuses and a
// StatusPolicy without RequireReference passes.
func FuzzStatusReference(f *testing.F) {
	f.Add(true, `{"status_list":{"idx":3,"uri":"https://status.example/1"}}`, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(true, `{"status_list":{"idx":-1,"uri":"https://status.example/1"}}`, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(true, `{"statuslist":{"idx":3,"uri":"https://status.example/1"}}`, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(true, `{"identifier_list":{"id":"AQ","uri":"https://status.example/1"}}`, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(true, `null`, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(true, `"https://status.example/1"`, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(true, `{}`, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(false, ``, uint8(1), uint64(0), "", []byte(nil), []byte(nil))
	f.Add(false, ``, uint8(2), uint64(9), "https://status.example/2", []byte(nil), []byte{0x30})
	f.Add(false, ``, uint8(3), uint64(0), "https://status.example/3", []byte{1, 2}, []byte(nil))
	f.Add(false, ``, uint8(4), uint64(1), "", []byte{}, []byte(nil))
	f.Add(false, ``, uint8(0), uint64(0), "", []byte(nil), []byte(nil))
	fetcher := statuslist.Fetcher{HTTP: &http.Client{Transport: refusingTransport{}}, UncheckedTransport: true}
	checker := statuslist.Checker{Fetcher: fetcher, Roots: x509.NewCertPool()}
	policies := []*verifier.StatusPolicy{
		{Checker: checker},
		{Checker: checker, StatusIssuers: verifier.AnyStatusListSigner},
	}
	f.Fuzz(func(t *testing.T, sdJWT bool, statusJSON string, mdocMode uint8, idx uint64, uri string, id, cert []byte) {
		vc := verifier.VerifiedCredential{CredentialQueryID: "q", Claims: map[string]any{"iss": "https://issuer.example"}}
		present := false
		if sdJWT {
			present = true
			var status any = statusJSON
			if json.Valid([]byte(statusJSON)) {
				if err := json.Unmarshal([]byte(statusJSON), &status); err != nil {
					t.Fatal(err)
				}
			}
			vc.Claims["status"] = status
		} else {
			vc.MdocStatus = fuzzMdocStatus(mdocMode, idx, uri, id, cert)
			present = vc.MdocStatus != nil
		}

		_, cwt, ok, err := vc.StatusListRef()
		identifierList := vc.MdocStatus != nil && vc.MdocStatus.IdentifierList != nil
		switch {
		case ok && err != nil:
			t.Fatalf("StatusListRef reported a reference and an error: %v", err)
		case present && !ok && err == nil:
			t.Fatalf("a present status (%q, mdoc %+v) read as no status", statusJSON, vc.MdocStatus)
		case !present && (ok || err != nil):
			t.Fatalf("no status read as %v, %v", ok, err)
		case ok && cwt != !sdJWT:
			t.Fatalf("StatusListRef cwt = %v for an SD-JWT VC: %v", cwt, sdJWT)
		}

		ctx := context.Background()
		result := verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{vc}}
		if refErr := verifier.RequireStatusReference(nil)(ctx, "tx", result); (refErr == nil) != (ok || identifierList) {
			t.Fatalf("RequireStatusReference = %v for a reference %v, identifier list %v", refErr, ok, identifierList)
		}
		for _, policy := range policies {
			checkErr := policy.Check(ctx, vc)
			if present && checkErr == nil {
				t.Fatalf("a status no list could be fetched for (%q, mdoc %+v) passed", statusJSON, vc.MdocStatus)
			}
			if !present && checkErr != nil {
				t.Fatalf("a credential with no status was refused: %v", checkErr)
			}
		}
	})
}

// fuzzMdocStatus is an MSO status: none (mode 0), neither member (1), a
// status list (2), an identifier list (3) or both (4).
func fuzzMdocStatus(mode uint8, idx uint64, uri string, id, cert []byte) *mdoc.Status {
	sl := &mdoc.StatusListRef{Idx: idx, URI: uri, Certificate: cert}
	il := &mdoc.IdentifierListRef{ID: id, URI: uri, Certificate: cert}
	switch mode % 5 {
	case 1:
		return &mdoc.Status{}
	case 2:
		return &mdoc.Status{StatusList: sl}
	case 3:
		return &mdoc.Status{IdentifierList: il}
	case 4:
		return &mdoc.Status{StatusList: sl, IdentifierList: il}
	}
	return nil
}
