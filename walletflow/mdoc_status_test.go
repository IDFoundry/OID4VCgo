package walletflow_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// storedMdoc is a wallet over client holding one mdoc, whose MSO's
// status is mutate's, valid until validUntil: its ID.
func storedMdoc(t *testing.T, client *http.Client, validUntil time.Time, mutate func(*mdoc.Claims)) (*walletflow.Wallet, string) {
	t.Helper()
	return storedFixture(t, client, validUntil, testmdoc.IssueWith(t, mutate))
}

// storedFixture is storedMdoc for f, an mdoc already issued.
func storedFixture(t *testing.T, client *http.Client, validUntil time.Time, f testmdoc.Fixture) (*walletflow.Wallet, string) {
	t.Helper()
	raw, err := f.IssuerSigned.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	mso, err := mdoc.IssuerAuthMSO(f.IssuerSigned)
	if err != nil {
		t.Fatal(err)
	}
	c := walletflow.StoredCredential{
		ID: "mdoc-1", CredentialIssuer: "https://issuer.example", Format: mdoc.CredentialFormat, DocType: testmdoc.DocType,
		Credential: base64.RawURLEncoding.EncodeToString(raw), ValidUntil: validUntil,
	}
	if mso.Status != nil && mso.Status.StatusList != nil {
		c.StatusList = &statuslist.StatusListRef{Idx: mso.Status.StatusList.Idx, URI: mso.Status.StatusList.URI}
		c.StatusListCWT = true
	}
	return walletHolding(t, client, c), c.ID
}

// walletHolding is a wallet over client whose store holds c.
func walletHolding(t *testing.T, client *http.Client, c walletflow.StoredCredential) *walletflow.Wallet {
	t.Helper()
	store := walletflow.NewMemoryCredentialStore()
	if err := store.Put(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	w, err := walletflow.New(walletflow.Config{Development: true}, walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: store, HTTP: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// An mdoc's status list is read as ISO/IEC 18013-5 §12.3.6.3 has it: a
// token without exp, or with its x5chain outside the protected header,
// is refused, not read.
func TestCheckStatus_MdocStatusListForm(t *testing.T) {
	signer := teststatuslist.NewSigner(t)
	for v, ok := range map[teststatuslist.Variant]bool{
		teststatuslist.WellFormed:         true,
		teststatuslist.NoExp:              false,
		teststatuslist.UnprotectedX5Chain: false,
	} {
		uri, client := signer.Serve(t, v)
		w, id := storedMdoc(t, client, time.Now().Add(time.Hour), func(c *mdoc.Claims) {
			c.Status = &mdoc.StatusListRef{Idx: 3, URI: uri, Certificate: signer.CA.Raw}
		})
		checked, err := w.CheckStatus(context.Background(), id)
		switch {
		case ok && (err != nil || checked.Status.Value != walletflow.StatusValid):
			t.Errorf("variant %d: CheckStatus = %+v, %v, want valid", v, checked.Status, err)
		case !ok && err == nil:
			t.Errorf("variant %d: CheckStatus = %+v, want it refused", v, checked.Status)
		}
	}
}

// An mdoc naming an identifier list, which the wallet can't check, is
// StatusUnknown, not left with no status as if it had none to check;
// an expired one is left as it is.
func TestCheckStatus_IdentifierListIsUnknown(t *testing.T) {
	listed := func(c *mdoc.Claims) {
		c.IdentifierList = &mdoc.IdentifierListRef{ID: []byte{7}, URI: "https://status.example/ids"}
	}
	w, id := storedMdoc(t, http.DefaultClient, time.Now().Add(time.Hour), listed)
	checked, err := w.CheckStatus(context.Background(), id)
	if err != nil || checked.Status.Value != walletflow.StatusUnknown || checked.Status.CheckedAt.IsZero() {
		t.Errorf("CheckStatus = %+v, %v, want unknown", checked.Status, err)
	}
	w, id = storedMdoc(t, http.DefaultClient, time.Now().Add(-time.Minute), listed)
	if checked, err := w.CheckStatus(context.Background(), id); err != nil || checked.Status.Value != "" {
		t.Errorf("expired: CheckStatus = %+v, %v, want no status", checked.Status, err)
	}
	w, id = storedMdoc(t, http.DefaultClient, time.Now().Add(time.Hour), func(*mdoc.Claims) {})
	if checked, err := w.CheckStatus(context.Background(), id); err != nil || checked.Status.Value != "" {
		t.Errorf("no status: CheckStatus = %+v, %v, want none", checked.Status, err)
	}
}
