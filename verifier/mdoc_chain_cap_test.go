package verifier_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// The failed-chain limit applies to mdocs as to SD-JWT VCs: a response
// whose distinct x5chains no root anchors is refused as a whole once
// MaxFailedIssuerChainsPerResponse of them have failed.
func TestVerifyResponse_RefusesAfterTooManyFailedMdocChains(t *testing.T) {
	ca, _ := testcert.CA(t, "document signer root")
	other, otherKey := testcert.CA(t, "untrusted root")
	mf := newMdocVerifyFixture(t)
	var presentations []string
	for i := range verifier.MaxFailedIssuerChainsPerResponse + 3 {
		// A document of its own each: one presented twice is refused
		// before its chain is looked at.
		f := testmdoc.Issue(t)
		protected, unprotected, payload, err := cose.DecodeUnverified(f.IssuerSigned.IssuerAuth)
		if err != nil {
			t.Fatal(err)
		}
		leaf, leafKey := testcert.Leaf(t, fmt.Sprintf("document signer %d", i), other, otherKey)
		unprotected.X5Chain = [][]byte{leaf.Raw}
		issuerSigned := f.IssuerSigned
		if issuerSigned.IssuerAuth, err = cose.Sign(cose.ES256, leafKey, protected, unprotected, payload, []byte{}); err != nil {
			t.Fatal(err)
		}
		presentations = append(presentations, presentDocument(t, oid4vpmdoc.Document{DocType: testmdoc.DocType, IssuerSigned: issuerSigned, DeviceSigned: mf.deviceSigned(t, f, nil)}))
	}
	query := mf.query
	query.Credentials = append([]dcql.CredentialQuery(nil), query.Credentials...)
	query.Credentials[0].Multiple = true

	_, err := mf.v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query, Response: verifier.ParsedResponse{VPToken: map[string][]string{"mdl": presentations}},
		ExpectedNonce: mf.nonce, ResponseEncryptionKey: mf.responseDecryptionKey,
		MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: certrevocation.NoCheck{}},
	})
	var vErr *verifier.Error
	if !errors.As(err, &vErr) || vErr.Reason() != verifier.ReasonMalformed || !strings.Contains(err.Error(), "failed to verify") {
		t.Fatalf("err = %v, want a malformed response refused for its failed chains", err)
	}
}
