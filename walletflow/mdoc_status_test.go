package walletflow_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
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
	c := mdocCredential(t, validUntil, f.IssuerSigned)
	return walletHolding(t, client, c), c.ID
}

// mdocCredential is the stored credential holding issued, valid until
// validUntil.
func mdocCredential(t *testing.T, validUntil time.Time, issued mdoc.IssuerSigned) walletflow.StoredCredential {
	t.Helper()
	raw, err := issued.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	mso, err := mdoc.IssuerAuthMSO(issued)
	if err != nil {
		t.Fatal(err)
	}
	c := walletflow.StoredCredential{
		ID: "mdoc-1", CredentialIssuer: "https://issuer.example", Format: mdoc.CredentialFormat, DocType: mso.DocType,
		Credential: base64.RawURLEncoding.EncodeToString(raw), ValidUntil: validUntil,
	}
	if mso.Status != nil && mso.Status.StatusList != nil {
		c.StatusList = &statuslist.StatusListRef{Idx: mso.Status.StatusList.Idx, URI: mso.Status.StatusList.URI}
		c.StatusListCWT = true
	}
	return c
}

// walletHolding is a wallet over client whose store holds c.
func walletHolding(t *testing.T, client *http.Client, c walletflow.StoredCredential) *walletflow.Wallet {
	t.Helper()
	return walletHoldingWith(t, walletflow.Config{Development: true}, client, c)
}

// walletHoldingWith is walletHolding with cfg.
func walletHoldingWith(t *testing.T, cfg walletflow.Config, client *http.Client, c walletflow.StoredCredential) *walletflow.Wallet {
	t.Helper()
	store := walletflow.NewMemoryCredentialStore()
	if err := store.Put(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	w, err := walletflow.New(cfg, walletflow.Dependencies{
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

// An mdoc's identifier list is checked, its signer bound to the mdoc's
// issuer: on it, the mdoc is revoked; off it, valid. Revoked on either
// of a status list and an identifier list it names, it's revoked. An
// expired mdoc is left as it is, and one with no status has nothing to
// check.
func TestCheckStatus_IdentifierList(t *testing.T) {
	signer := teststatuslist.NewSigner(t)
	other := teststatuslist.NewSigner(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		id         byte
		statusList bool
		pin        *x509.Certificate
		want       string // "" for refused
	}{
		"not listed":                   {id: 2, pin: signer.CA, want: walletflow.StatusValid},
		"listed":                       {id: 7, pin: signer.CA, want: walletflow.StatusInvalid},
		"listed, valid on status list": {id: 7, statusList: true, pin: signer.CA, want: walletflow.StatusInvalid},
		"not listed, with status list": {id: 2, statusList: true, pin: signer.CA, want: walletflow.StatusValid},
		"signer under another CA":      {id: 2, pin: other.CA},
	} {
		t.Run(name, func(t *testing.T) {
			statusURI, idsURI, client := signer.ServeLists(t, teststatuslist.WellFormed, []byte{7})
			var pin []byte
			if tc.pin != nil {
				pin = tc.pin.Raw
			}
			status := mdoc.Status{IdentifierList: &mdoc.IdentifierListRef{ID: []byte{tc.id}, URI: idsURI, Certificate: pin}}
			if tc.statusList {
				// mdoc.Issue names one mechanism; an MSO may name both.
				status.StatusList = &mdoc.StatusListRef{Idx: 3, URI: statusURI, Certificate: signer.CA.Raw}
			}
			w, id := storedFixture(t, client, time.Now().Add(time.Hour), testmdoc.WithMSOStatus(t, testmdoc.Issue(t), status))
			checked, err := w.CheckStatus(ctx, id)
			switch {
			case tc.want == "" && err == nil:
				t.Errorf("CheckStatus = %+v, want it refused", checked.Status)
			case tc.want != "" && (err != nil || checked.Status.Value != tc.want || checked.Status.CheckedAt.IsZero()):
				t.Errorf("CheckStatus = %+v, %v, want %s", checked.Status, err, tc.want)
			}
		})
	}

	listed := func(c *mdoc.Claims) {
		c.IdentifierList = &mdoc.IdentifierListRef{ID: []byte{7}, URI: "https://status.example/ids"}
	}
	w, id := storedMdoc(t, http.DefaultClient, time.Now().Add(-time.Minute), listed)
	if checked, err := w.CheckStatus(ctx, id); err != nil || checked.Status.Value != "" {
		t.Errorf("expired: CheckStatus = %+v, %v, want no status", checked.Status, err)
	}
	w, id = storedMdoc(t, http.DefaultClient, time.Now().Add(time.Hour), func(*mdoc.Claims) {})
	if checked, err := w.CheckStatus(ctx, id); err != nil || checked.Status.Value != "" {
		t.Errorf("no status: CheckStatus = %+v, %v, want none", checked.Status, err)
	}
}

// An identifier list whose MSO names no Certificate is signed under
// the CA that signed the mdoc's document signer (ISO/IEC 18013-5
// §12.3.6.2): not under another of the wallet's mdoc roots.
func TestCheckStatus_IdentifierListUnderIssuerCA(t *testing.T) {
	iaca, iacaKey := testcert.CA(t, "IACA")
	otherCA, otherKey := testcert.CA(t, "Other IACA")
	ds, dsKey := testcert.Leaf(t, "Document signer", iaca, iacaKey)
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	roots.AddCert(otherCA)
	for name, tc := range map[string]struct {
		ca   *x509.Certificate
		key  *ecdsa.PrivateKey
		id   byte
		want string // "" for refused
	}{
		"same IACA, listed":     {iaca, iacaKey, 7, walletflow.StatusInvalid},
		"same IACA, not listed": {iaca, iacaKey, 2, walletflow.StatusValid},
		"another trusted IACA":  {otherCA, otherKey, 2, ""},
	} {
		t.Run(name, func(t *testing.T) {
			leaf, leafKey := testcert.Leaf(t, "List signer", tc.ca, tc.key)
			signer := teststatuslist.Signer{CA: tc.ca, Key: leafKey, Chain: []*x509.Certificate{leaf}}
			_, uri, client := signer.ServeLists(t, teststatuslist.WellFormed, []byte{7})
			c := mdocCredential(t, time.Now().Add(time.Hour), issueUnder(t, ds, dsKey, func(c *mdoc.Claims) {
				c.IdentifierList = &mdoc.IdentifierListRef{ID: []byte{tc.id}, URI: uri}
			}))
			w := walletHoldingWith(t, walletflow.Config{Development: true, MdocIssuerRoots: roots}, client, c)
			checked, err := w.CheckStatus(context.Background(), c.ID)
			switch {
			case tc.want == "" && err == nil:
				t.Errorf("CheckStatus = %+v, want it refused", checked.Status)
			case tc.want != "" && (err != nil || checked.Status.Value != tc.want):
				t.Errorf("CheckStatus = %+v, %v, want %s", checked.Status, err, tc.want)
			}
		})
	}
}

// A copy found revoked stays revoked (ISO/IEC 18013-5 §12.3.6.1): its
// list served later saying otherwise, an older one say, isn't fetched
// while the copy is live. Once it has expired, the others are checked.
func TestCheckStatus_RevocationIsFinal(t *testing.T) {
	signer := teststatuslist.NewSigner(t)
	ctx := context.Background()
	revokedAt := time.Now().Add(-time.Hour).UTC()

	// Found revoked now, on the list, then served a list without it.
	var list atomic.Pointer[[]byte]
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", identifierlist.MediaType)
		_, _ = w.Write(*list.Load())
	}))
	t.Cleanup(srv.Close)
	uri := srv.URL + "/ids"
	revoking, older := signer.IdentifierList(t, uri, []byte{7}), signer.IdentifierList(t, uri)
	list.Store(&revoking)
	listed := mdocCredential(t, time.Now().Add(time.Hour), testmdoc.IssueWith(t, func(c *mdoc.Claims) {
		c.IdentifierList = &mdoc.IdentifierListRef{ID: []byte{7}, URI: uri, Certificate: signer.CA.Raw}
	}).IssuerSigned)
	listed.Copies = []walletflow.CredentialCopy{{Credential: listed.Credential}}
	w := walletHolding(t, srv.Client(), listed)
	checked, err := w.CheckStatus(ctx, listed.ID)
	if err != nil || checked.Status.Value != walletflow.StatusInvalid || !checked.Copies[0].Revoked {
		t.Fatalf("listed: CheckStatus = %+v, %v; want invalid, the copy revoked", checked, err)
	}
	list.Store(&older)
	if again, err := w.CheckStatus(ctx, listed.ID); err != nil || again.Status != checked.Status {
		t.Errorf("served an older list: CheckStatus = %+v, %v; want %+v still", again.Status, err, checked.Status)
	}

	_, valid, client := signer.ServeLists(t, teststatuslist.WellFormed)
	f := testmdoc.IssueWith(t, func(c *mdoc.Claims) {
		c.IdentifierList = &mdoc.IdentifierListRef{ID: []byte{7}, URI: valid, Certificate: signer.CA.Raw}
	})
	for name, tc := range map[string]struct {
		copies       []walletflow.CredentialCopy // nil: stored before copies were kept
		stillRevoked bool
	}{
		"one copy, stored before copies were kept": {nil, true},
		"revoked copy live":                        {[]walletflow.CredentialCopy{{Revoked: true}, {}}, true},
		"revoked copy expired":                     {[]walletflow.CredentialCopy{{Revoked: true, ValidUntil: time.Now().Add(-time.Minute)}, {}}, false},
	} {
		t.Run(name, func(t *testing.T) {
			c := mdocCredential(t, time.Now().Add(time.Hour), f.IssuerSigned)
			c.Status = walletflow.CredentialStatus{Value: walletflow.StatusInvalid, CheckedAt: revokedAt}
			for _, cp := range tc.copies {
				cp.Credential = c.Credential
				c.Copies = append(c.Copies, cp)
			}
			checked, err := walletHolding(t, client, c).CheckStatus(ctx, c.ID)
			switch {
			case err != nil:
				t.Errorf("CheckStatus: %v", err)
			case tc.stillRevoked && (checked.Status.Value != walletflow.StatusInvalid || !checked.Status.CheckedAt.Equal(revokedAt)):
				t.Errorf("CheckStatus = %+v, want it still invalid as of %v, not checked again", checked.Status, revokedAt)
			case !tc.stillRevoked && checked.Status.Value != walletflow.StatusValid:
				t.Errorf("CheckStatus = %+v, want the live copy checked: valid", checked.Status)
			}
		})
	}
}

// issueUnder is an mdoc signed by dsKey, ds's, its claims mutate's.
func issueUnder(t *testing.T, ds *x509.Certificate, dsKey *ecdsa.PrivateKey, mutate func(*mdoc.Claims)) mdoc.IssuerSigned {
	t.Helper()
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := mdoc.Claims{
		DocType:    testmdoc.DocType,
		NameSpaces: map[string]map[string]any{testmdoc.Namespace: {"given_name": "Alice"}},
		DeviceKey:  &device.PublicKey, Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}
	mutate(&claims)
	issued, err := mdoc.Issue(dsKey, cose.ES256, claims, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	return issued
}
