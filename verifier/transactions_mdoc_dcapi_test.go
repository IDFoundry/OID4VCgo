package verifier_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

const (
	mdocDocType = "org.iso.18013.5.1.mDL"
	mdocNS      = "org.iso.18013.5.1"
)

// mdocTxFixture is a Transactions for org-iso-mdoc requests, an mDL
// issued under an IACA it trusts, and the holder's device key.
type mdocTxFixture struct {
	t            *testing.T
	txs          *verifier.Transactions
	store        verifier.TransactionStore
	now          time.Time
	issuerSigned mdoc.IssuerSigned
	deviceKey    *ecdsa.PrivateKey
	readerRoots  *x509.CertPool
}

type mdocTxOptions struct {
	// statusURI, if set, is the status list the mDL's MSO names, at
	// index 0, checked through client.
	statusURI string
	client    *http.Client
	iaca      *x509.Certificate
	iacaKey   *ecdsa.PrivateKey
	store     verifier.TransactionStore
	verifier  *verifier.Verifier
	tweak     func(*verifier.TransactionsConfig)
}

func newMdocTxFixture(t *testing.T, o mdocTxOptions) *mdocTxFixture {
	t.Helper()
	if o.iaca == nil {
		o.iaca, o.iacaKey = newIACA(t, "mdoc tx IACA")
	}
	ds, dsKey := testcert.Issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "mdoc tx document signer", Country: o.iaca.Subject.Country},
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU},
	}, o.iaca, o.iacaKey)
	deviceKey := testP256Key(t)
	now := time.Now()
	claims := mdoc.Claims{
		DocType:    mdocDocType,
		NameSpaces: map[string]map[string]any{mdocNS: {"given_name": "Alice", "age_over_18": true, "family_name": "Doe"}},
		DeviceKey:  &deviceKey.PublicKey, Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour),
	}
	if o.statusURI != "" {
		claims.Status = &mdoc.StatusListRef{Idx: 0, URI: o.statusURI}
	}
	issuerSigned, err := mdoc.Issue(dsKey, cose.ES256, claims, mdoc.IssueOptions{X5Chain: [][]byte{ds.Raw}})
	if err != nil {
		t.Fatal(err)
	}
	readerCA, readerCAKey := testcert.CA(t, "mdoc tx reader CA")
	readerCert, readerKey := testcert.Leaf(t, "mdoc tx reader", readerCA, readerCAKey)
	protocol, err := mdocdcapi.ForTransactions(mdocdcapi.ReaderKey{Signer: readerKey, Chain: []*x509.Certificate{readerCert}})
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(o.iaca)
	readerRoots := x509.NewCertPool()
	readerRoots.AddCert(readerCA)

	f := &mdocTxFixture{t: t, now: now, issuerSigned: issuerSigned, deviceKey: deviceKey, readerRoots: readerRoots}
	cfg := verifier.TransactionsConfig{
		Origins: []string{dcapiOrigin}, MdocDCAPI: protocol,
		Verify: verifier.VerifyResponseRequest{
			MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}},
			Now:            func() time.Time { return f.now },
		},
	}
	if o.statusURI != "" {
		cfg.Status = &verifier.StatusPolicy{Checker: statuslist.Checker{
			Fetcher: statuslist.Fetcher{HTTP: o.client, AllowLoopback: true}, Roots: roots,
		}}
	}
	if o.tweak != nil {
		o.tweak(&cfg)
	}
	f.store = o.store
	if f.store == nil {
		f.store = storage.NewVerifierTransactionStore()
	}
	v := o.verifier
	if v == nil {
		v = newTestVerifier(t)
	}
	if f.txs, err = verifier.NewTransactions(v, f.store, cfg); err != nil {
		t.Fatalf("NewTransactions: %v", err)
	}
	return f
}

// newIACA is an IACA certificate, with the countryName its document
// signers must share (ISO/IEC 18013-5 Annex B).
func newIACA(t *testing.T, name string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return testcert.CAWithSubject(t, pkix.Name{CommonName: name, Country: []string{"UT"}})
}

func mdocRequest() verifier.MdocDCAPIRequest {
	return verifier.MdocDCAPIRequest{DocType: mdocDocType, Elements: map[string]map[string]bool{mdocNS: {"given_name": true, "age_over_18": false}}}
}

func (f *mdocTxFixture) begin(binding string) verifier.BegunMdocDCAPI {
	f.t.Helper()
	begun, err := f.txs.BeginMdocDCAPI(context.Background(), mdocRequest(), binding, dcapiOrigin)
	if err != nil {
		f.t.Fatalf("BeginMdocDCAPI: %v", err)
	}
	return begun
}

// answer is the platform's data for the wallet's answer to begun, from
// a page at origin, disclosing elements.
func (f *mdocTxFixture) answer(begun verifier.BegunMdocDCAPI, origin string, elements ...[2]string) []byte {
	f.t.Helper()
	data, err := json.Marshal(begun.Request.Data)
	if err != nil {
		f.t.Fatal(err)
	}
	in, err := mdocdcapi.ParseRequest(data, origin)
	if err != nil {
		f.t.Fatalf("ParseRequest: %v", err)
	}
	// The reader signed over the request's own origin: one the wallet is
	// told is another doesn't verify.
	if _, err := in.VerifyReaderTrust(mdocdcapi.ReaderTrust{Roots: f.readerRoots, Now: time.Now(), Revocation: certrevocation.NoCheck{}}); (err == nil) != (origin == dcapiOrigin) {
		f.t.Fatalf("VerifyReaderTrust from %s: %v", origin, err)
	}
	if len(elements) == 0 {
		elements = [][2]string{{mdocNS, "given_name"}, {mdocNS, "age_over_18"}}
	}
	encrypted, err := in.Respond(0, f.issuerSigned, f.deviceKey, elements)
	if err != nil {
		f.t.Fatalf("Respond: %v", err)
	}
	return mdocdcapi.ResponseData(encrypted)
}

func TestTransactions_MdocDCAPI(t *testing.T) {
	f := newMdocTxFixture(t, mdocTxOptions{})
	ctx := context.Background()
	begun := f.begin(testBinding)
	if begun.Request.Protocol != mdocdcapi.Protocol || begun.Request.Data.DeviceRequest == "" || begun.Request.Data.EncryptionInfo == "" {
		t.Fatalf("request = %+v", begun.Request)
	}
	// The page's JSON is Annex C.2's data.
	encoded, err := json.Marshal(begun.Request)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"protocol":"org-iso-mdoc","data":{"deviceRequest":`) {
		t.Errorf("request JSON = %s", encoded)
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, testBinding); err != nil || view.Status != verifier.TransactionPending {
		t.Fatalf("Lookup before the answer: %+v, %v", view, err)
	}

	view, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, dcapiOrigin))
	if err != nil {
		t.Fatalf("HandleMdocDCAPIResponse: %v", err)
	}
	if view.Status != verifier.TransactionDone || view.Result == nil || len(view.Result.Credentials) != 1 {
		t.Fatalf("view = %+v", view)
	}
	vc := view.Result.Credentials[0]
	if vc.CredentialQueryID != verifier.MdocDCAPICredentialQueryID || len(vc.IssuerChain) == 0 {
		t.Errorf("credential = %+v", vc)
	}
	elements, _ := vc.Claims[mdocNS].(map[string]any)
	if elements["given_name"] != "Alice" || elements["age_over_18"] != true || elements["family_name"] != nil {
		t.Errorf("claims = %v", vc.Claims)
	}
	if looked, err := f.txs.Lookup(ctx, begun.ID, testBinding); err != nil || looked.Status != verifier.TransactionDone || looked.Result == nil {
		t.Errorf("Lookup after the answer: %+v, %v", looked, err)
	}
	// Completes once: the same response replayed, or another valid one.
	replayed := f.answer(begun, dcapiOrigin)
	for range 2 {
		if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, replayed); !errors.Is(err, verifier.ErrTransactionAnswered) {
			t.Errorf("second answer: %v, want ErrTransactionAnswered", err)
		}
	}
	if err := f.txs.Forget(ctx, begun.ID); err != nil {
		t.Fatal(err)
	}
	if looked, err := f.txs.Lookup(ctx, begun.ID, testBinding); err != nil || looked.Status != verifier.TransactionClosed || looked.Result != nil {
		t.Errorf("Lookup after Forget: %+v, %v", looked, err)
	}
}

// The verified document carries the request's CredentialQueryID, so an
// Accept shared with OpenID4VP requests reads it as its own query's.
func TestTransactions_MdocDCAPICredentialQueryID(t *testing.T) {
	var accepted verifier.VerifyResponseResult
	f := newMdocTxFixture(t, mdocTxOptions{tweak: func(cfg *verifier.TransactionsConfig) {
		cfg.Accept = func(_ context.Context, _ string, result verifier.VerifyResponseResult) error {
			accepted = result
			return nil
		}
	}})
	req := mdocRequest()
	req.CredentialQueryID = "mdl"
	begun, err := f.txs.BeginMdocDCAPI(context.Background(), req, testBinding, dcapiOrigin)
	if err != nil {
		t.Fatal(err)
	}
	view, err := f.txs.HandleMdocDCAPIResponse(context.Background(), begun.ID, testBinding, f.answer(begun, dcapiOrigin))
	if err != nil {
		t.Fatal(err)
	}
	if view.Result.Credentials[0].CredentialQueryID != "mdl" || len(accepted.Credentials) != 1 || accepted.Credentials[0].CredentialQueryID != "mdl" {
		t.Errorf("result %+v, accepted %+v", view.Result, accepted)
	}
	req.CredentialQueryID = "not an id"
	if _, err := f.txs.BeginMdocDCAPI(context.Background(), req, testBinding, dcapiOrigin); err == nil {
		t.Error("an invalid CredentialQueryID was accepted")
	}
}

// An answer withholding a requested element is refused, as an
// OpenID4VP answer not satisfying its Credential Query is, and the
// request stays open — unless the request allows it, when it completes
// with Withheld naming what's missing, for Accept and in the stored
// result.
func TestTransactions_MdocDCAPIWithheldElements(t *testing.T) {
	var accepted []verifier.VerifyResponseResult
	f := newMdocTxFixture(t, mdocTxOptions{tweak: func(cfg *verifier.TransactionsConfig) {
		cfg.Accept = func(_ context.Context, _ string, result verifier.VerifyResponseResult) error {
			accepted = append(accepted, result)
			return nil
		}
	}})
	ctx := context.Background()
	begun := f.begin(testBinding)
	_, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, dcapiOrigin, [2]string{mdocNS, "age_over_18"}))
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonNotAnswered || !strings.Contains(err.Error(), mdocNS+"/given_name") {
		t.Errorf("an answer withholding given_name: %v, want ReasonNotAnswered naming it", err)
	}
	if view, _ := f.txs.Lookup(ctx, begun.ID, testBinding); view.Status != verifier.TransactionPending || !strings.Contains(view.LastError, "not_answered") {
		t.Errorf("after the refused answer: %+v", view)
	}
	if len(accepted) != 0 {
		t.Errorf("Accept ran on a refused answer: %+v", accepted)
	}
	// The full answer still completes it, with nothing withheld.
	view, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, dcapiOrigin))
	if err != nil {
		t.Fatal(err)
	}
	if w := view.Result.Credentials[0].Withheld; w != nil {
		t.Errorf("Withheld = %v for a full answer", w)
	}

	req := mdocRequest()
	req.AllowWithheld = true
	allowing, err := f.txs.BeginMdocDCAPI(ctx, req, testBinding, dcapiOrigin)
	if err != nil {
		t.Fatal(err)
	}
	view, err = f.txs.HandleMdocDCAPIResponse(ctx, allowing.ID, testBinding, f.answer(allowing, dcapiOrigin, [2]string{mdocNS, "age_over_18"}))
	if err != nil {
		t.Fatalf("an answer withholding an element of a request allowing it: %v", err)
	}
	want := map[string][]string{mdocNS: {"given_name"}}
	if got := view.Result.Credentials[0].Withheld; !reflect.DeepEqual(got, want) {
		t.Errorf("Withheld = %v, want %v", got, want)
	}
	if len(accepted) != 2 || !reflect.DeepEqual(accepted[1].Credentials[0].Withheld, want) {
		t.Errorf("Accept saw %+v", accepted)
	}
	if looked, err := f.txs.Lookup(ctx, allowing.ID, testBinding); err != nil || looked.Result == nil || !reflect.DeepEqual(looked.Result.Credentials[0].Withheld, want) {
		t.Errorf("Lookup: %+v, %v", looked, err)
	}
}

func TestTransactions_MdocDCAPIRefusals(t *testing.T) {
	f := newMdocTxFixture(t, mdocTxOptions{})
	ctx := context.Background()
	begun := f.begin(testBinding)

	// Another browser's post is refused, and leaves the request as it was.
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, "another-browser-binding", f.answer(begun, dcapiOrigin)); !errors.Is(err, verifier.ErrWrongBrowser) {
		t.Errorf("another browser: %v, want ErrWrongBrowser", err)
	}
	if view, _ := f.txs.Lookup(ctx, begun.ID, testBinding); view.LastError != "" {
		t.Errorf("another browser's post was recorded: %q", view.LastError)
	}
	// Answered to a page at another origin: the session transcript binds
	// the request's own origin, so the response doesn't decrypt.
	_, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, "https://attacker.example.com"))
	var verr *verifier.Error
	if !errors.As(err, &verr) || verr.Reason() != verifier.ReasonMdocDCAPIResponse {
		t.Errorf("an answer bound to another origin: %v, want ReasonMdocDCAPIResponse", err)
	}
	if view, _ := f.txs.Lookup(ctx, begun.ID, testBinding); view.Status != verifier.TransactionPending || !strings.Contains(view.LastError, "mdoc_dcapi_response") {
		t.Errorf("after a refused answer: %+v", view)
	}
	for name, data := range map[string]string{
		"not JSON":          "response",
		"no response":       `{}`,
		"an error member":   `{"error":"access_denied"}`,
		"not base64url":     `{"response":"!!"}`,
		"an unknown member": `{"response":"AA","other":1}`,
		"over the size cap": `{"response":"` + strings.Repeat("a", verifier.MaxMdocDCAPIResponseBytes) + `"}`,
	} {
		if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, []byte(data)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A valid answer behind a member another parser would read instead.
	valid := f.answer(begun, dcapiOrigin)
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, append([]byte(`{"Response":"x",`), valid[1:]...)); err == nil {
		t.Error("a case-variant duplicate member was accepted")
	}
	// Still answerable: none of the refusals spent it.
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, valid); err != nil {
		t.Errorf("the valid answer after the refusals: %v", err)
	}
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, "no-such-request", testBinding, valid); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("an unknown request: %v", err)
	}
}

func TestTransactions_MdocDCAPIExpiryAndClose(t *testing.T) {
	f := newMdocTxFixture(t, mdocTxOptions{})
	ctx := context.Background()
	begun := f.begin(testBinding)
	answer := f.answer(begun, dcapiOrigin)
	f.now = f.now.Add(11 * time.Minute)
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, answer); !errors.Is(err, verifier.ErrTransactionExpired) {
		t.Errorf("after expiry: %v, want ErrTransactionExpired", err)
	}
	f.now = time.Now()
	closed := f.begin(testBinding)
	if err := f.txs.Close(ctx, closed.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, closed.ID, testBinding, f.answer(closed, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionClosed) {
		t.Errorf("after Close: %v, want ErrTransactionClosed", err)
	}
}

// Neither Digital Credentials API protocol's handler completes the
// other's request, nor do the redirect flow's.
func TestTransactions_MdocDCAPIFlowsKeptApart(t *testing.T) {
	f := newTxFixture(t, func(cfg *verifier.TransactionsConfig) {
		cfg.Origins = []string{dcapiOrigin}
	})
	m := newMdocTxFixture(t, mdocTxOptions{store: f.store, verifier: f.v, tweak: func(cfg *verifier.TransactionsConfig) {
		cfg.RequestURIBase, cfg.RedirectURI = txBase, "https://verifier.example.com/continue?x=1"
		cfg.Verify.IssuerKeys, cfg.Verify.MaxKeyBindingAge = f.verify.IssuerKeys, time.Hour
	}})
	ctx := context.Background()
	openid := f.beginDCAPI(testBinding)
	mdocBegun := m.begin(testBinding)
	if _, err := m.txs.HandleMdocDCAPIResponse(ctx, openid.ID, testBinding, m.answer(mdocBegun, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("an OpenID4VP request's ID to HandleMdocDCAPIResponse: %v, want ErrTransactionUnknown", err)
	}
	if _, err := m.txs.HandleDCAPIResponse(ctx, mdocBegun.ID, testBinding, f.dcapiAnswer(openid, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("an org-iso-mdoc request's ID to HandleDCAPIResponse: %v, want ErrTransactionUnknown", err)
	}
	redirect, err := m.txs.Begin(ctx, f.query, testBinding, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.txs.HandleMdocDCAPIResponse(ctx, redirect.ID, testBinding, m.answer(mdocBegun, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("a redirect request's ID to HandleMdocDCAPIResponse: %v, want ErrTransactionUnknown", err)
	}
	if _, err := m.txs.RequestObject(ctx, mdocBegun.ID); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("RequestObject of an org-iso-mdoc request: %v, want ErrTransactionUnknown", err)
	}
	// Each still completes through its own handler.
	if _, err := m.txs.HandleMdocDCAPIResponse(ctx, mdocBegun.ID, testBinding, m.answer(mdocBegun, dcapiOrigin)); err != nil {
		t.Errorf("the org-iso-mdoc answer: %v", err)
	}
	if _, err := m.txs.HandleDCAPIResponse(ctx, openid.ID, testBinding, f.dcapiAnswer(openid, dcapiOrigin)); err != nil {
		t.Errorf("the OpenID4VP answer: %v", err)
	}
}

func TestTransactions_MdocDCAPIBeginRefusals(t *testing.T) {
	f := newMdocTxFixture(t, mdocTxOptions{})
	ctx := context.Background()
	for name, tc := range map[string]struct {
		req             verifier.MdocDCAPIRequest
		binding, origin string
	}{
		"origin not in Origins":  {mdocRequest(), testBinding, "https://attacker.example.com"},
		"short browser binding":  {mdocRequest(), "short", dcapiOrigin},
		"no doctype":             {verifier.MdocDCAPIRequest{Elements: mdocRequest().Elements}, testBinding, dcapiOrigin},
		"no elements":            {verifier.MdocDCAPIRequest{DocType: mdocDocType}, testBinding, dcapiOrigin},
		"an empty namespace":     {verifier.MdocDCAPIRequest{DocType: mdocDocType, Elements: map[string]map[string]bool{mdocNS: {}}}, testBinding, dcapiOrigin},
		"an unnamed namespace":   {verifier.MdocDCAPIRequest{DocType: mdocDocType, Elements: map[string]map[string]bool{"": {"x": false}}}, testBinding, dcapiOrigin},
		"an unnamed element":     {verifier.MdocDCAPIRequest{DocType: mdocDocType, Elements: map[string]map[string]bool{mdocNS: {"": false}}}, testBinding, dcapiOrigin},
		"an origin with a path":  {mdocRequest(), testBinding, dcapiOrigin + "/page"},
		"an http origin":         {mdocRequest(), testBinding, "http://verifier.example.com"},
		"an origin not normal'd": {mdocRequest(), testBinding, "https://other.example.com:443"},
	} {
		if _, err := f.txs.BeginMdocDCAPI(ctx, tc.req, tc.binding, tc.origin); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An origin as a browser may spell it is normalized first.
	if _, err := f.txs.BeginMdocDCAPI(ctx, mdocRequest(), testBinding, "HTTPS://Verifier.Example.com:443"); err != nil {
		t.Errorf("an origin in another spelling: %v", err)
	}

	// Without the protocol, or the mdoc issuer keys.
	for name, tweak := range map[string]func(*verifier.TransactionsConfig){
		"no MdocDCAPI":      func(cfg *verifier.TransactionsConfig) { cfg.MdocDCAPI = nil },
		"no MdocIssuerKeys": func(cfg *verifier.TransactionsConfig) { cfg.Verify.MdocIssuerKeys = nil },
	} {
		g := newMdocTxFixture(t, mdocTxOptions{tweak: tweak})
		if _, err := g.txs.BeginMdocDCAPI(ctx, mdocRequest(), testBinding, dcapiOrigin); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A reader key BuildRequest would refuse is refused up front.
	if _, err := mdocdcapi.ForTransactions(mdocdcapi.ReaderKey{Signer: testP256Key(t)}); err == nil {
		t.Error("ForTransactions accepted a reader key without a certificate")
	}
}

// A store that changes the request's Query or EncryptionInfo has its
// sealed record refused: neither opens under another binding.
func TestTransactions_MdocDCAPISealed(t *testing.T) {
	codec := verifier.TransactionCodec{Sealer: testSealer(t)}
	store := newCodecStore(codec)
	f := newMdocTxFixture(t, mdocTxOptions{store: store})
	ctx := context.Background()
	begun := f.begin(testBinding)
	row := store.rows[begun.ID]
	var record map[string]any
	if err := json.Unmarshal(row, &record); err != nil {
		t.Fatal(err)
	}
	if record["mdoc_encryption_info"] != begun.Request.Data.EncryptionInfo || record["response_decryption_key"] == nil {
		t.Fatalf("record = %s", row)
	}
	for name, alter := range map[string]func(map[string]any){
		"encryption info removed": func(r map[string]any) { delete(r, "mdoc_encryption_info") },
		"encryption info changed": func(r map[string]any) { r["mdoc_encryption_info"] = "AAAA" },
		"query changed": func(r map[string]any) {
			r["query"].(map[string]any)["credentials"].([]any)[0].(map[string]any)["meta"] = map[string]any{"doctype_value": "org.example.other"}
		},
		"origin changed":      func(r map[string]any) { r["origin"] = "https://attacker.example.com" },
		"withholding allowed": func(r map[string]any) { r["mdoc_allow_withheld"] = true },
	} {
		var copied map[string]any
		if err := json.Unmarshal(row, &copied); err != nil {
			t.Fatal(err)
		}
		alter(copied)
		tampered, err := json.Marshal(copied)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := codec.Unmarshal(tampered); err == nil {
			t.Errorf("%s: the tampered record opened", name)
		}
	}
	// The record as written opens, and the request completes, its claims
	// sealed in turn.
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, dcapiOrigin)); err != nil {
		t.Fatalf("HandleMdocDCAPIResponse: %v", err)
	}
	if strings.Contains(string(store.rows[begun.ID]), "Alice") {
		t.Error("the completed record holds the claims unsealed")
	}
	view, err := f.txs.Lookup(ctx, begun.ID, testBinding)
	if err != nil || view.Result == nil || view.Result.Credentials[0].Claims[mdocNS].(map[string]any)["given_name"] != "Alice" {
		t.Errorf("Lookup: %+v, %v", view, err)
	}

	// A request allowing withheld elements binds that too: its record
	// doesn't open once a store makes it require them all.
	req := mdocRequest()
	req.AllowWithheld = true
	allowing, err := f.txs.BeginMdocDCAPI(ctx, req, testBinding, dcapiOrigin)
	if err != nil {
		t.Fatal(err)
	}
	var allowingRecord map[string]any
	if err := json.Unmarshal(store.rows[allowing.ID], &allowingRecord); err != nil {
		t.Fatal(err)
	}
	if allowingRecord["mdoc_allow_withheld"] != true {
		t.Fatalf("record = %s", store.rows[allowing.ID])
	}
	delete(allowingRecord, "mdoc_allow_withheld")
	tampered, err := json.Marshal(allowingRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.Unmarshal(tampered); err == nil {
		t.Error("a record whose withholding was disallowed opened")
	}
	if _, err := codec.Unmarshal(store.rows[allowing.ID]); err != nil {
		t.Errorf("the record as written: %v", err)
	}
}

// The document's revocation status is checked (TransactionsConfig.Status)
// with the list's signer bound to its issuer: a revoked mDL is refused
// as a Status refusal, its text kept as LastError, the request still
// open.
func TestTransactions_MdocDCAPIStatus(t *testing.T) {
	iaca, iacaKey := newIACA(t, "mdoc tx status IACA")
	signer, signerKey := testcert.Leaf(t, "mdoc tx status signer", iaca, iacaKey)
	revoked := map[string]bool{"/revoked": true, "/valid": false}
	var base string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bad, ok := revoked[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		status := uint8(0)
		if bad {
			status = 1
		}
		sl, err := statuslist.New(statuslist.Bits1, []uint8{status}, "")
		if err != nil {
			t.Error(err)
			return
		}
		exp := time.Now().Add(time.Hour).Unix()
		token, err := statuslist.IssueTokenCWTX5Chain(signerKey, cose.ES256, statuslist.TokenClaims{
			Sub: base + r.URL.Path, Iat: time.Now().Unix(), Exp: &exp, StatusList: sl,
		}, []*x509.Certificate{signer})
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", statuslist.CWTTokenMediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	base = srv.URL
	ctx := context.Background()

	valid := newMdocTxFixture(t, mdocTxOptions{statusURI: base + "/valid", client: srv.Client(), iaca: iaca, iacaKey: iacaKey})
	begun := valid.begin(testBinding)
	if _, err := valid.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, valid.answer(begun, dcapiOrigin)); err != nil {
		t.Errorf("a valid mDL: %v", err)
	}

	f := newMdocTxFixture(t, mdocTxOptions{statusURI: base + "/revoked", client: srv.Client(), iaca: iaca, iacaKey: iacaKey})
	begun = f.begin(testBinding)
	_, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, dcapiOrigin))
	var notValid *statuslist.NotValidError
	if !errors.As(err, &notValid) || notValid.Status != statuslist.StatusInvalid {
		t.Fatalf("a revoked mDL: %v, want a statuslist.NotValidError", err)
	}
	view, err := f.txs.Lookup(ctx, begun.ID, testBinding)
	if err != nil || view.Status != verifier.TransactionPending || !strings.Contains(view.LastError, "status") {
		t.Errorf("after the revoked mDL: %+v, %v", view, err)
	}
}

// Under AssuranceProduction, an org-iso-mdoc request needs Origins and a
// sealing store, as an OpenID4VP one does, and completes end to end with
// them.
func TestTransactions_MdocDCAPIProduction(t *testing.T) {
	cfg, deps := validConfig(t)
	caIssuedClientCert(t, &cfg, &deps)
	cfg.Assurance = verifier.AssuranceProduction
	prod, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	sound := func(c *verifier.TransactionsConfig) {
		c.NoStatusCheck, c.Verify.AnyIssuerForAnyType = true, true
	}
	ctx := context.Background()

	// No Origins, and no RequestURIBase: nothing to serve.
	plain := newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)})
	noOrigins := func(c *verifier.TransactionsConfig) { sound(c); c.Origins = nil }
	if _, err := verifier.NewTransactions(prod, assuredTransactionStore{plain}, mdocConfigFor(t, noOrigins)); err == nil {
		t.Error("a Digital Credentials API-only production Transactions without Origins was accepted")
	}
	// With a RequestURIBase but no Origins, Begin refuses each request.
	withBase := func(c *verifier.TransactionsConfig) { noOrigins(c); c.RequestURIBase = txBase }
	txs, err := verifier.NewTransactions(prod, assuredTransactionStore{plain}, mdocConfigFor(t, withBase))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txs.BeginMdocDCAPI(ctx, mdocRequest(), testBinding, dcapiOrigin); err == nil || !strings.Contains(err.Error(), "Origins") {
		t.Errorf("BeginMdocDCAPI without Origins under production: %v", err)
	}
	// An unsealed store.
	if _, err := verifier.NewTransactions(prod, unsealedTransactionStore{plain}, mdocConfigFor(t, sound)); err == nil {
		t.Error("an unsealed store was accepted under production")
	}

	f := newMdocTxFixture(t, mdocTxOptions{store: assuredTransactionStore{plain}, verifier: prod, tweak: sound})
	begun := f.begin(testBinding)
	if _, err := f.txs.BeginMdocDCAPI(ctx, verifier.MdocDCAPIRequest{DocType: mdocDocType}, testBinding, dcapiOrigin); err == nil {
		t.Error("a request with no elements was accepted under production")
	}
	view, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, dcapiOrigin))
	if err != nil || view.Status != verifier.TransactionDone {
		t.Fatalf("under production: %+v, %v", view, err)
	}
}

// mdocConfigFor is a TransactionsConfig for org-iso-mdoc requests, with
// tweak applied.
func mdocConfigFor(t *testing.T, tweak func(*verifier.TransactionsConfig)) verifier.TransactionsConfig {
	t.Helper()
	iaca, _ := testcert.CA(t, "mdoc config IACA")
	roots := x509.NewCertPool()
	roots.AddCert(iaca)
	protocol, err := mdocdcapi.ForTransactions()
	if err != nil {
		t.Fatal(err)
	}
	cfg := verifier.TransactionsConfig{
		Origins: []string{dcapiOrigin}, MdocDCAPI: protocol,
		Verify: verifier.VerifyResponseRequest{MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}},
	}
	tweak(&cfg)
	return cfg
}

// A store that drops MdocEncryptionInfo is refused when the first
// org-iso-mdoc request is created, as one that drops Origin is.
func TestTransactions_MdocDCAPIStoreMustKeepEncryptionInfo(t *testing.T) {
	f := newMdocTxFixture(t, mdocTxOptions{store: droppingStore{storage.NewVerifierTransactionStore()}})
	if _, err := f.txs.BeginMdocDCAPI(context.Background(), mdocRequest(), testBinding, dcapiOrigin); err == nil || !strings.Contains(err.Error(), "MdocEncryptionInfo") {
		t.Errorf("a store that drops MdocEncryptionInfo: %v", err)
	}
}

// faultyProtocol is an MdocDCAPIProtocol whose request comes back
// incomplete, or not at all.
type faultyProtocol struct{ built verifier.MdocDCAPIBuilt }

func (p faultyProtocol) BuildMdocDCAPIRequest(verifier.MdocDCAPIBuild) (verifier.MdocDCAPIBuilt, error) {
	if p.built.RecipientKey == nil && p.built.Data.DeviceRequest == "" {
		return verifier.MdocDCAPIBuilt{}, errors.New("no request")
	}
	return p.built, nil
}

func (faultyProtocol) VerifyMdocDCAPIResponse(context.Context, verifier.MdocDCAPIVerify) (verifier.VerifiedCredential, error) {
	return verifier.VerifiedCredential{}, errors.New("not verified")
}

// A request the protocol fails to build, or builds without its key or
// data, isn't begun.
func TestTransactions_MdocDCAPIBuildFaults(t *testing.T) {
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := verifier.MdocDCAPIRequestData{DeviceRequest: "AA", EncryptionInfo: "AA"}
	for name, built := range map[string]verifier.MdocDCAPIBuilt{
		"an error":         {},
		"no key":           {Data: data},
		"an X25519 key":    {Data: data, RecipientKey: x25519},
		"no DeviceRequest": {Data: verifier.MdocDCAPIRequestData{EncryptionInfo: "AA"}, RecipientKey: key},
	} {
		f := newMdocTxFixture(t, mdocTxOptions{tweak: func(cfg *verifier.TransactionsConfig) { cfg.MdocDCAPI = faultyProtocol{built} }})
		if _, err := f.txs.BeginMdocDCAPI(context.Background(), mdocRequest(), testBinding, dcapiOrigin); err == nil {
			t.Errorf("%s: begun", name)
		}
	}
}

// A store that changed an unsealed request's Query fails the answer as
// the Verifier's own fault, not the wallet's.
func TestTransactions_MdocDCAPIQueryChangedInTheStore(t *testing.T) {
	ctx := context.Background()
	for name, alter := range map[string]func(*verifier.Transaction){
		"two credentials": func(tx *verifier.Transaction) {
			tx.Query.Credentials = append(tx.Query.Credentials, tx.Query.Credentials[0])
		},
		"no meta": func(tx *verifier.Transaction) { tx.Query.Credentials[0].Meta = nil },
		"a claim that isn't an element": func(tx *verifier.Transaction) {
			tx.Query.Credentials[0].Claims[0].Path = tx.Query.Credentials[0].Claims[0].Path[:1]
		},
		"no claims": func(tx *verifier.Transaction) { tx.Query.Credentials[0].Claims = nil },
	} {
		f := newMdocTxFixture(t, mdocTxOptions{})
		begun := f.begin(testBinding)
		if err := f.store.Update(ctx, begun.ID, func(tx *verifier.Transaction) error {
			alter(tx)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		_, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, f.answer(begun, dcapiOrigin))
		var verr *verifier.Error
		if err == nil || errors.As(err, &verr) {
			t.Errorf("%s: %v, want the Verifier's own fault", name, err)
		}
	}
}

// A refusal repeated — a flood of unauthenticated answers — is written
// to the store once, while each different one is still recorded, and
// OnRefused still sees every one.
func TestTransactions_RepeatedRefusalWrittenOnce(t *testing.T) {
	store := &countingStore{TransactionStore: storage.NewVerifierTransactionStore()}
	refused := 0
	f := newMdocTxFixture(t, mdocTxOptions{store: store, tweak: func(cfg *verifier.TransactionsConfig) {
		cfg.OnRefused = func(context.Context, string, error) { refused++ }
	}})
	ctx := context.Background()
	begun := f.begin(testBinding)
	malformed := []byte(`{"response":"!!"}`)
	for range 5 {
		if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, malformed); err == nil {
			t.Fatal("a malformed answer was accepted")
		}
	}
	if store.saved != 1 || refused != 5 {
		t.Errorf("5 identical refusals: %d store writes, OnRefused %d times; want 1 and 5", store.saved, refused)
	}
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, []byte(`{}`)); err == nil {
		t.Fatal("an answer without a response was accepted")
	}
	if view, _ := f.txs.Lookup(ctx, begun.ID, testBinding); store.saved != 2 || !strings.Contains(view.LastError, "(malformed)") {
		t.Errorf("another refusal: %d store writes, LastError %q", store.saved, view.LastError)
	}
	if _, err := f.txs.HandleMdocDCAPIResponse(ctx, begun.ID, testBinding, malformed); err == nil {
		t.Fatal("a malformed answer was accepted")
	}
	if store.saved != 3 {
		t.Errorf("the first refusal again, after another: %d store writes, want 3", store.saved)
	}
}

// countingStore counts the Updates that save.
type countingStore struct {
	verifier.TransactionStore
	saved int
}

func (s *countingStore) Update(ctx context.Context, id string, fn func(*verifier.Transaction) error) error {
	return s.TransactionStore.Update(ctx, id, func(tx *verifier.Transaction) error {
		err := fn(tx)
		if err == nil {
			s.saved++
		}
		return err
	})
}

// droppingStore loses every transaction's MdocEncryptionInfo.
type droppingStore struct{ verifier.TransactionStore }

func (s droppingStore) Create(ctx context.Context, tx verifier.Transaction) error {
	tx.MdocEncryptionInfo = ""
	return s.TransactionStore.Create(ctx, tx)
}
