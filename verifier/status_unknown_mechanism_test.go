package verifier_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// A credential whose status names only a mechanism this library
// doesn't know — a future one, or a misspelt key — is refused by
// RequireValidStatus in either format, not passed as having no status:
// a credential revoked through that mechanism would pass.
func TestRequireValidStatus_UnknownMechanism(t *testing.T) {
	unknown := map[string]any{"status_List": map[string]any{"idx": 7, "uri": "https://issuer.example/sl/1"}}
	f := testmdoc.WithMSOStatus(t, testmdoc.Issue(t), unknown)
	verified, err := mdoc.Verify(f.IssuerSigned, testmdoc.DocType, &f.IssuerKey.PublicKey, cose.ES256, mdoc.VerifyOptions{Now: time.Now})
	if err != nil {
		t.Fatalf("mdoc.Verify: %v", err)
	}
	if verified.Status == nil {
		t.Fatal("the MSO's unrecognised status decoded as no status")
	}
	accept := verifier.RequireValidStatus(statuslist.Checker{Roots: x509.NewCertPool()})
	creds := map[string]verifier.VerifiedCredential{
		"mdoc":   {CredentialQueryID: "q", MdocStatus: verified.Status, Claims: map[string]any{}},
		"sd-jwt": {CredentialQueryID: "q", Claims: map[string]any{"iss": "https://issuer.example", "status": map[string]any{"status_List": map[string]any{"idx": 7.0, "uri": "https://issuer.example/sl/1"}}}},
	}
	for name, vc := range creds {
		if err := accept(context.Background(), "", verifier.VerifyResponseResult{Credentials: []verifier.VerifiedCredential{vc}}); err == nil {
			t.Errorf("%s with an unknown status mechanism: RequireValidStatus passed it", name)
		}
	}
}
