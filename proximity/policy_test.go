package proximity

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// noStatusList is a status policy that can be configured but never
// fetches: its documents in these tests name no status list.
func noStatusList() *verifier.StatusPolicy {
	return &verifier.StatusPolicy{Checker: statuslist.Checker{Roots: x509.NewCertPool(), Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}}}}
}

// NewReaderSession requires an assurance level and a document signer
// revocation choice, and under AssuranceProduction the issuer and
// status decisions a Verifier makes there.
func TestNewReaderSession_Decisions(t *testing.T) {
	prod := []ReaderOption{WithAssurance(verifier.AssuranceProduction), WithIssuerRevocation(certrevocation.NoCheck{})}
	with := func(base []ReaderOption, opts ...ReaderOption) []ReaderOption {
		return append(append([]ReaderOption{}, base...), opts...)
	}
	for name, tc := range map[string]struct {
		opts    []ReaderOption
		refused string
	}{
		"no assurance":                   {[]ReaderOption{WithIssuerRevocation(certrevocation.NoCheck{})}, "assurance level is required"},
		"an unknown assurance":           {[]ReaderOption{WithAssurance(verifier.AssuranceLevel(9)), WithIssuerRevocation(certrevocation.NoCheck{})}, "assurance level is required"},
		"no revocation choice":           {[]ReaderOption{WithAssurance(verifier.AssuranceDevelopment)}, "WithIssuerRevocation is required"},
		"development":                    {devReader(), ""},
		"status and none":                {devReader(WithStatus(noStatusList()), WithNoStatusCheck()), "not both"},
		"a status without roots":         {devReader(WithStatus(&verifier.StatusPolicy{})), "Roots is required"},
		"production, no issuer decision": {with(prod, WithNoStatusCheck()), "WithIssuerAuthorization"},
		"production, no status decision": {with(prod, WithAnyIssuerForAnyType()), "set Status"},
		"production, unhardened status fetcher": {with(prod, WithAnyIssuerForAnyType(), WithStatus(&verifier.StatusPolicy{Checker: statuslist.Checker{
			Roots: x509.NewCertPool(), Fetcher: statuslist.Fetcher{AllowLoopback: true}, Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
		}})), "HardenedForProduction"},
		"production, system roots by type": {with(prod, WithAnyIssuerForAnyType(), WithNoStatusCheck(), WithIssuerRootsByDocType(map[string]*x509.CertPool{mDL: systemPool(t)})), "system root pool"},
		"production, decided":              {with(prod, WithAnyIssuerForAnyType(), WithNoStatusCheck()), ""},
		"production, authorized, status":   {with(prod, WithIssuerAuthorization(func(context.Context, verifier.IssuerAuthorization) error { return nil }), WithStatus(noStatusList())), ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewReaderSession(mustQR(t), tc.opts...)
			switch {
			case tc.refused == "" && err != nil:
				t.Errorf("NewReaderSession: %v", err)
			case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
				t.Errorf("NewReaderSession: %v, want it refused naming %q", err, tc.refused)
			}
		})
	}
}

// systemPool is the system root pool, or the test is skipped where
// there's none.
func systemPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system root pool: %v", err)
	}
	return pool
}

// Under AssuranceProduction, Verify refuses the system root pool as the
// document's trust anchors.
func TestVerify_ProductionRefusesSystemRoots(t *testing.T) {
	fx := issueFixture(t, mDL)
	f := establishWith(t, mDL, ageOver18, nil, []ReaderOption{
		WithAssurance(verifier.AssuranceProduction), WithIssuerRevocation(certrevocation.NoCheck{}), WithAnyIssuerForAnyType(), WithNoStatusCheck(),
	})
	_, err := f.reader.Verify(context.Background(), f.respond(t, fx, f.req.Elements), systemPool(t), time.Now())
	if err == nil || !strings.Contains(err.Error(), "system root pool") {
		t.Fatalf("Verify with the system roots: %v, want refused", err)
	}
}

// WithIssuerAuthorization decides on the verified document's type and
// issuer chain, and its refusal refuses the document.
func TestVerify_IssuerAuthorization(t *testing.T) {
	fx := issueFixture(t, mDL)
	refusal := errors.New("not this issuer's type")
	for name, want := range map[string]error{"accepted": nil, "refused": refusal} {
		t.Run(name, func(t *testing.T) {
			var got verifier.IssuerAuthorization
			f := establishReader(t, mDL, ageOver18, WithIssuerAuthorization(func(_ context.Context, a verifier.IssuerAuthorization) error {
				got = a
				return want
			}))
			_, err := f.reader.Verify(context.Background(), f.respond(t, fx, f.req.Elements), fx.roots, time.Now())
			if !errors.Is(err, want) {
				t.Fatalf("Verify: %v, want %v", err, want)
			}
			if got.Format != mdoc.CredentialFormat || got.Type != mDL || len(got.RequestedTypes) != 1 || got.RequestedTypes[0] != mDL ||
				len(got.MatchedTypes) != 1 || got.MatchedTypes[0] != mDL {
				t.Errorf("IssuerAuthorization types: %+v", got)
			}
			// The document signer, without the IACA it chains to.
			if len(got.IssuerChain) != 1 || !bytes.Equal(got.IssuerChain[0], fx.signer.Raw) {
				t.Errorf("IssuerAuthorization.IssuerChain has %d certificates, want the document signer's", len(got.IssuerChain))
			}
			if _, ok := got.Claims[mDLNS].(map[string]any)["age_over_18"]; !ok {
				t.Errorf("IssuerAuthorization.Claims = %v", got.Claims)
			}
		})
	}
}

// WithStatus checks the verified document's status in Verify: a policy
// requiring a status reference refuses a document naming none, and one
// that doesn't accepts it.
func TestVerify_Status(t *testing.T) {
	fx := issueFixture(t, mDL)
	for name, requireReference := range map[string]bool{"accepted": false, "refused": true} {
		t.Run(name, func(t *testing.T) {
			policy := noStatusList()
			policy.RequireReference = requireReference
			f := establishReader(t, mDL, ageOver18, WithStatus(policy))
			_, err := f.reader.Verify(context.Background(), f.respond(t, fx, f.req.Elements), fx.roots, time.Now())
			if (err != nil) != requireReference {
				t.Fatalf("Verify: %v, want refused %v", err, requireReference)
			}
		})
	}
}

// Verified.Credential is the document as a verifier.VerifiedCredential,
// so verifier.RequireValidStatus takes it.
func TestVerified_Credential(t *testing.T) {
	fx := issueFixture(t, mDL)
	f := establishReader(t, mDL, ageOver18)
	v, err := f.reader.Verify(context.Background(), f.respond(t, fx, f.req.Elements), fx.roots, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	vc := v.Credential()
	if vc.MdocStatus != v.Status || vc.CredentialQueryID != "" {
		t.Errorf("Credential() = %+v", vc)
	}
	if len(vc.IssuerChain) != len(v.IssuerChain)-1 || !bytes.Equal(vc.IssuerChain[0], v.IssuerChain[0].Raw) {
		t.Errorf("Credential().IssuerChain has %d certificates; Verified.IssuerChain %d, anchor included", len(vc.IssuerChain), len(v.IssuerChain))
	}
	if vc.Claims[mDLNS].(map[string]any)["age_over_18"] != true {
		t.Errorf("Credential().Claims = %v", vc.Claims)
	}
	accept := verifier.RequireValidStatus(noStatusList().Checker)
	if err := accept(context.Background(), "", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{vc}}); err != nil {
		t.Errorf("RequireValidStatus on a document naming no status: %v", err)
	}
	if one := (Verified{IssuerChain: v.IssuerChain[len(v.IssuerChain)-1:]}).Credential(); len(one.IssuerChain) != 1 {
		t.Errorf("a one-certificate chain lost its certificate: %d", len(one.IssuerChain))
	}
}
