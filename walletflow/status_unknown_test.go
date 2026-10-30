package walletflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// unknownStatus is a status naming only a mechanism the wallet doesn't
// know: a misspelt status_list.
var unknownStatus = map[string]any{"status_List": map[string]any{"idx": 7, "uri": "https://status.example/1"}}

// A credential whose status names no mechanism the wallet knows is
// StatusUnknown, in either format, not left with no status as if it had
// none to check: that mechanism may still revoke it.
func TestCheckStatus_UnknownMechanismIsUnknown(t *testing.T) {
	until := time.Now().Add(time.Hour)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exp := until.Unix()
	sdjwt, _, err := sdjwtvc.Issue(key, jose.ES256, sdjwtvc.Claims{VCT: "urn:x", Exp: &exp, Status: unknownStatus}, sdjwtvc.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mdocWallet, mdocID := storedFixture(t, http.DefaultClient, until, testmdoc.WithMSOStatus(t, testmdoc.Issue(t), unknownStatus))
	sdjwtWallet := walletHolding(t, http.DefaultClient, walletflow.StoredCredential{
		ID: "sd-jwt-1", CredentialIssuer: "https://issuer.example", Format: sdjwtvc.CredentialFormat, VCT: "urn:x",
		Credential: sdjwt, ValidUntil: until,
	})
	for name, tc := range map[string]struct {
		w  *walletflow.Wallet
		id string
	}{
		"mdoc":      {mdocWallet, mdocID},
		"SD-JWT VC": {sdjwtWallet, "sd-jwt-1"},
	} {
		checked, err := tc.w.CheckStatus(context.Background(), tc.id)
		if err != nil || checked.Status.Value != walletflow.StatusUnknown {
			t.Errorf("%s: CheckStatus = %+v, %v, want unknown", name, checked.Status, err)
		}
	}
}
