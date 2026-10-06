package walletflow_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

const (
	shopOrigin  = "https://shop.example"
	otherOrigin = "https://other.example"
)

// mdocReader signs org-iso-mdoc requests with a certificate from its CA.
type mdocReader struct {
	key   mdocdcapi.ReaderKey
	roots *x509.CertPool
}

func newMdocReader(t *testing.T) mdocReader {
	t.Helper()
	ca, caKey := testcert.CA(t, "walletflow test reader CA")
	cert, key := testcert.Leaf(t, "walletflow test reader", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return mdocReader{key: mdocdcapi.ReaderKey{Signer: key, Chain: []*x509.Certificate{cert, ca}}, roots: roots}
}

// ask builds a request from origin for the test mdoc's family_name,
// which the reader will keep, and given_name: the request's data, and
// what the reader keeps to verify the answer.
func (r mdocReader) ask(t *testing.T, origin string) ([]byte, mdocdcapi.Pending) {
	t.Helper()
	req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin: origin, DocType: walletflowtest.DocType, Readers: []mdocdcapi.ReaderKey{r.key},
		Elements: map[string]map[string]bool{walletflowtest.NameSpace: {"family_name": true, "given_name": false}},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(req.Data)
	if err != nil {
		t.Fatal(err)
	}
	return data, req.Pending
}

func mdocWallet(t *testing.T, f fixture, readerRoots *x509.CertPool, policy walletflow.CopyPolicy) *walletflow.Wallet {
	t.Helper()
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		MdocReaderRoots: readerRoots, Development: true, CopyPolicy: policy,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func familyName() [][2]string { return [][2]string{{walletflowtest.NameSpace, "family_name"}} }

func TestMdocPresentation(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	reader := newMdocReader(t)
	w := mdocWallet(t, f, reader.roots, walletflow.CopyPerPresentation)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	var mdocID string
	for _, c := range held {
		if c.Format == "mso_mdoc" {
			mdocID = c.ID
		}
	}
	ctx := context.Background()
	data, pending := reader.ask(t, shopOrigin)

	p, err := w.StartMdocPresentation(ctx, data, shopOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if p.Origin() != shopOrigin || p.Reader() == nil || !p.Reader().Equal(reader.key.Chain[0]) {
		t.Errorf("Origin %q, Reader %v", p.Origin(), p.Reader())
	}
	requests := p.Requests()
	want := []walletflow.MdocElement{{Namespace: walletflowtest.NameSpace, Identifier: "family_name", Retain: true}, {Namespace: walletflowtest.NameSpace, Identifier: "given_name"}}
	if len(requests) != 1 || requests[0].DocType != walletflowtest.DocType || len(requests[0].Elements) != 2 ||
		requests[0].Elements[0] != want[0] || requests[0].Elements[1] != want[1] ||
		len(requests[0].Credentials) != 1 || requests[0].Credentials[0].ID != mdocID {
		t.Fatalf("Requests = %+v", requests)
	}
	if p.Linkable(mdocID) {
		t.Error("an unused copy is linkable")
	}

	presented, err := p.Respond(ctx, 0, mdocID, familyName())
	if err != nil {
		t.Fatal(err)
	}
	got, err := mdocdcapi.VerifyResponse(ctx, mdocdcapi.VerifyParams{
		Pending: pending, Response: base64.RawURLEncoding.EncodeToString(presented.EncryptedResponse),
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: f.env.IssuerRoots},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.NameSpaces[walletflowtest.NameSpace]["family_name"] != walletflowtest.FamilyName || len(got.NameSpaces[walletflowtest.NameSpace]) != 1 {
		t.Errorf("disclosed %v, want only family_name", got.NameSpaces)
	}
	if presented.Linkable {
		t.Error("Presented.Linkable for an unused copy")
	}
	if _, err := p.Respond(ctx, 0, mdocID, familyName()); !errors.Is(err, walletflow.ErrWrongStep) {
		t.Errorf("a second Respond = %v, want ErrWrongStep", err)
	}
	stored, err := f.store.Get(ctx, mdocID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.ShownTo("origin:" + shopOrigin) {
		t.Error("the copy doesn't record the origin it was shown to")
	}
}

// A reader the wallet doesn't recognize, or any reader when the wallet
// recognizes none, is shown by origin only, and can still be answered.
func TestMdocPresentation_UnrecognizedReader(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	other := newMdocReader(t)
	for name, roots := range map[string]*x509.CertPool{"no roots": nil, "another CA": other.roots} {
		t.Run(name, func(t *testing.T) {
			w := mdocWallet(t, f, roots, walletflow.CopyPerPresentation)
			id := receive(t, f, w, walletflowtest.MdocConfigurationID)[0].ID
			data, _ := newMdocReader(t).ask(t, shopOrigin)
			p, err := w.StartMdocPresentation(context.Background(), data, shopOrigin)
			if err != nil {
				t.Fatal(err)
			}
			if p.Reader() != nil {
				t.Errorf("Reader = %v, want nil", p.Reader().Subject)
			}
			if _, err := p.Respond(context.Background(), 0, id, familyName()); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestMdocPresentation_RefusesSelection(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	reader := newMdocReader(t)
	w := mdocWallet(t, f, reader.roots, walletflow.CopyPerPresentation)
	held := receive(t, f, w, walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
	ids := map[string]string{}
	for _, c := range held {
		ids[c.Format] = c.ID
	}
	data, _ := reader.ask(t, shopOrigin)
	ctx := context.Background()
	p, err := w.StartMdocPresentation(ctx, data, shopOrigin)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		request  int
		id       string
		elements [][2]string
	}{
		"no such request":     {1, ids["mso_mdoc"], familyName()},
		"not held":            {0, "missing", familyName()},
		"an SD-JWT VC":        {0, ids["dc+sd-jwt"], familyName()},
		"nothing to disclose": {0, ids["mso_mdoc"], nil},
		"unrequested element": {0, ids["mso_mdoc"], [][2]string{{walletflowtest.NameSpace, "portrait"}}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := p.Respond(ctx, c.request, c.id, c.elements); !errors.Is(err, walletflow.ErrInvalidSelection) {
				t.Errorf("Respond = %v, want ErrInvalidSelection", err)
			}
		})
	}
	// None of those answered it.
	if _, err := p.Respond(ctx, 0, ids["mso_mdoc"], familyName()); err != nil {
		t.Error(err)
	}
}

// With one copy, presenting to a second origin hands it a copy the first
// has seen: Linkable says so beforehand and Presented afterwards.
func TestMdocPresentation_LinkableAcrossOrigins(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 1})
	reader := newMdocReader(t)
	w := mdocWallet(t, f, reader.roots, walletflow.CopyPerPresentation)
	id := receive(t, f, w, walletflowtest.MdocConfigurationID)[0].ID
	ctx := context.Background()
	present := func(origin string) (bool, walletflow.MdocPresented) {
		data, _ := reader.ask(t, origin)
		p, err := w.StartMdocPresentation(ctx, data, origin)
		if err != nil {
			t.Fatal(err)
		}
		linkable := p.Linkable(id)
		presented, err := p.Respond(ctx, 0, id, familyName())
		if err != nil {
			t.Fatal(err)
		}
		return linkable, presented
	}
	if linkable, presented := present(shopOrigin); linkable || presented.Linkable {
		t.Error("the first presentation is linkable")
	}
	if linkable, presented := present(otherOrigin); !linkable || !presented.Linkable {
		t.Errorf("the only copy, seen by %s, presented to %s: Linkable %v, Presented.Linkable %v", shopOrigin, otherOrigin, linkable, presented.Linkable)
	}
}

// A response that couldn't be built leaves the copy unused, and the
// presentation unanswered.
func TestMdocPresentation_FailureReleasesTheCopy(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 1})
	reader := newMdocReader(t)
	w := mdocWallet(t, f, reader.roots, walletflow.CopyPerPresentation)
	c := receive(t, f, w, walletflowtest.MdocConfigurationID)[0]
	ctx := context.Background()
	data, _ := reader.ask(t, shopOrigin)
	p, err := w.StartMdocPresentation(ctx, data, shopOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.keys.DeleteKey(ctx, c.HolderKeyID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Respond(ctx, 0, c.ID, familyName()); err == nil {
		t.Fatal("Respond without the holder key succeeded")
	}
	stored, err := f.store.Get(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cp := stored.AllCopies()[0]; cp.Presented || len(cp.ShownTo) != 0 {
		t.Errorf("after a failed Respond the copy is %+v", cp)
	}
}

func TestStartMdocPresentation_RefusesMalformed(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	w := mdocWallet(t, f, nil, walletflow.CopyPerPresentation)
	if _, err := w.StartMdocPresentation(context.Background(), []byte("{}"), shopOrigin); err == nil {
		t.Error("an empty request parsed")
	}
	data, _ := newMdocReader(t).ask(t, shopOrigin)
	if _, err := w.StartMdocPresentation(context.Background(), data, shopOrigin+"/"); err == nil {
		t.Error("an origin with a path was accepted")
	}
}
